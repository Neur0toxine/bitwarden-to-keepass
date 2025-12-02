import json
import logging
import subprocess
import base64
import uuid
from argparse import Namespace

from pykeepass import PyKeePass, entry, create_database
from pykeepass.exceptions import CredentialsError

from src.folder import load_folders
from src.item import CustomFieldType, Item, ItemType
from src.set_kp_entry_urls import set_kp_entry_urls

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s :: %(levelname)s :: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

def bitwarden_to_keepass(args: Namespace) -> None:
    try:
        kp = PyKeePass(
            args.database_path,
            password=args.database_password,
            keyfile=args.database_keyfile,
        )
    except FileNotFoundError:
        logging.info("KeePass database does not exist, creating a new one.")
        kp = create_database(
            args.database_path,
            password=args.database_password,
            keyfile=args.database_keyfile,
        )
    except CredentialsError:
        logging.exception("Wrong password for KeePass database")
        return

    folders = subprocess.check_output(
        [args.bw_path, "list", "folders", "--session", args.bw_session],
        encoding="utf8",
    )
    folders = json.loads(folders)
    groups_by_id = load_folders(kp, folders)
    logging.info("Folders done (%d).", len(groups_by_id))

    items = subprocess.check_output(
        [args.bw_path, "list", "items", "--session", args.bw_session],
        encoding="utf8",
    )
    items = json.loads(items)
    logging.info("Starting to process %d items.", len(items))
    for item in items:
        if item["type"] in [ItemType.CARD, ItemType.IDENTITY]:
            logging.warning("Skipping credit card or identity item %s.", item["name"])
            continue

        bw_item = Item(item)

        is_duplicate_title = False
        try:
            while True:
                entry_title = (
                    bw_item.get_name()
                    if not is_duplicate_title
                    else f"{bw_item.get_name()} - ({bw_item.get_id()}"
                )
                try:
                    entry = kp.add_entry(
                        destination_group=groups_by_id[bw_item.get_folder_id()],
                        title=entry_title,
                        username=bw_item.get_username(),
                        password=bw_item.get_password(),
                        notes=bw_item.get_notes(),
                    )
                    break
                except Exception as e:
                    if "already exists" in str(e):
                        is_duplicate_title = True
                        continue
                    raise

            totp_secret, totp_settings = bw_item.get_totp()
            if totp_secret and totp_settings:
                entry.set_custom_property("TOTP Seed", totp_secret, protect=True)
                entry.set_custom_property("TOTP Settings", totp_settings)

            uris = [uri["uri"] for uri in bw_item.get_uris()]
            set_kp_entry_urls(entry, uris)

            for field in bw_item.get_custom_fields():
                entry.set_custom_property(
                    field["name"],
                    field["value"],
                    protect=field["type"] == CustomFieldType.HIDDEN,
                )

            if item["type"] == ItemType.SSHKEY:
                add_ssh_key(kp, entry, bw_item)
            
            add_passkeys(kp, entry, bw_item)
            add_attachments(kp, entry, bw_item, args)

        except Exception as e:
            logging.warning(
                "Skipping item named %s because of this error: %s",
                item["name"],
                e,
            )
            continue

    logging.info("Saving changes to KeePass database.")
    kp.save()
    logging.info("Export completed.")

def add_ssh_key (kp: PyKeePass, entry: entry.Entry, bw_item: Item) -> None:
    settings_id = kp.add_binary('''<?xml version="1.0" encoding="UTF-16"?>
<EntrySettings xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <AllowUseOfSshKey>true</AllowUseOfSshKey>
  <AddAtDatabaseOpen>true</AddAtDatabaseOpen>
  <RemoveAtDatabaseClose>true</RemoveAtDatabaseClose>
  <UseConfirmConstraintWhenAdding>false</UseConfirmConstraintWhenAdding>
  <UseLifetimeConstraintWhenAdding>false</UseLifetimeConstraintWhenAdding>
  <LifetimeConstraintDuration>600</LifetimeConstraintDuration>
  <Location>
    <SelectedType>attachment</SelectedType>
    <AttachmentName>{}</AttachmentName>
    <SaveAttachmentToTempFile>false</SaveAttachmentToTempFile>
    <FileName/>
  </Location>
</EntrySettings>
'''.format("id_ssh").encode("utf-16le"))
    entry.add_attachment(settings_id, "KeeAgent.settings")
    attachment_id = kp.add_binary(bw_item.get_ssh_key())
    entry.add_attachment(attachment_id, "id_ssh")

def add_passkeys(kp: PyKeePass, entry: entry.Entry, bw_item: Item) -> None:
    """Convert Bitwarden FIDO2 credentials to KeePassXC passkey format."""
    fido2_credentials = bw_item.get_fido2_credentials()
    
    if not fido2_credentials:
        return
    
    for passkey in fido2_credentials:
        try:
            credential_id = passkey.get_credential_id()
            if credential_id:
                uuid_hex = uuid.UUID(credential_id).hex
                credential_bytes = bytes.fromhex(uuid_hex)
                credential_id_b64 = base64.urlsafe_b64encode(credential_bytes).decode('utf-8').rstrip('=')
                entry.set_custom_property("KPEX_PASSKEY_CREDENTIAL_ID", credential_id_b64, protect=True)
            
            key_value = passkey.get_key_value()
            if key_value:
                key_bytes = base64.urlsafe_b64decode(key_value + '==')  # Add padding if needed
                key_b64 = base64.b64encode(key_bytes).decode('utf-8')
                private_key_pem = (
                    "-----BEGIN PRIVATE KEY-----\n"
                    f"{key_b64}\n"
                    "-----END PRIVATE KEY-----"
                )
                entry.set_custom_property("KPEX_PASSKEY_PRIVATE_KEY_PEM", private_key_pem, protect=True)
            
            user_handle = passkey.get_user_handle()
            if user_handle:
                entry.set_custom_property("KPEX_PASSKEY_USER_HANDLE", user_handle, protect=True)
                        
            user_name = passkey.get_user_name()
            if user_name:
                entry.set_custom_property("KPEX_PASSKEY_USERNAME", user_name)
            
            rp_id = passkey.get_rp_id()
            if rp_id:
                entry.set_custom_property("KPEX_PASSKEY_RELYING_PARTY", rp_id)
            
            if entry.tags:
                if "Passkey" not in entry.tags:
                    entry.tags.append("Passkey")
            else:
                entry.tags = ["Passkey"]
                
        except Exception as e:
            logging.warning(
                "Failed to convert passkey for entry %s: %s",
                bw_item.get_name(),
                e,
            )
            continue

def add_attachments (kp: PyKeePass, entry: entry.Entry, bw_item: Item, args: Namespace) -> None:
    for attachment in bw_item.get_attachments():
        attachment_raw = subprocess.check_output(
            [
                args.bw_path,
                "get",
                "attachment",
                attachment["id"],
                        "--raw",
                "--itemid",
                bw_item.get_id(),
                "--session",
                args.bw_session,
            ],
        )
        attachment_id = kp.add_binary(attachment_raw)
        entry.add_attachment(attachment_id, attachment["fileName"])