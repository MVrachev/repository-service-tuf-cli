# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT
import copy
import sys
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from rich import align, box, markdown, prompt, table, text
from rich.style import Style
from securesystemslib.exceptions import StorageError  # type: ignore
from securesystemslib.signer import Key, Signature  # type: ignore
from tuf.api.exceptions import UnsignedMetadataError
from tuf.api.metadata import Metadata, Root
from tuf.api.serialization import DeserializationError

from repository_service_tuf.cli import click, console
from repository_service_tuf.cli.admin import admin
from repository_service_tuf.helpers.api_client import (
    URL,
    Methods,
    get_md_file,
    request_server,
    send_payload,
    task_status,
)
from repository_service_tuf.helpers.tuf import (
    MetadataInfo,
    RSTUFKey,
    get_rstuf_key,
    load_key_ask_info,
    load_payload,
    save_payload,
)

INTRODUCTION = """
# Metadata Update

The metadata update ceremony allows to:
- extend Root expiration
- change Root signature threshold
- change any signing key
"""

CURRENT_ROOT_INFO = """
# Current Root Content

Before deciding what you want to update it's recommended that you
get familiar with the current state of the root metadata file.
"""

AUTHORIZATION = """
# STEP 1: Authorization

Before continuing, you must authorize yourself.

To complete the authorization you will be asked to provide information
about one of the keys used to sign the current root metadata.
You will need local access to the key as well as its corresponding password.
"""

EXPIRY_CHANGES_MSG = """
# STEP 2: Extend Root Expiration

Now, you will be given the opportunity to extend root's expiration.

Note: the root expiration can be extended ONLY during the metadata update
ceremony.
"""

ROOT_KEYS_CHANGES_MSG = """
# STEP 3:  Root Keys Changes

You are starting the Root keys changes procedure.

Note: when asked about specific attributes the default values that are
suggested will be the ones used in the current root metadata.
"""

ROOT_KEYS_REMOVAL_MSG = """
## Root Keys Removal

You are starting the root keys modification procedure.

First, you will be asked if you want to remove any of the keys.
Then you will be given the opportunity to add as many keys as you want.

In the end, the number of keys that are left must be equal or above the
threshold you have given.
"""

ROOT_KEY_ADDITIONS_MSG = """
## Root Keys Addition

Now, you will be able to add root keys.
"""

ONLINE_KEY_CHANGE = """
# STEP 4: Online Key Change

Now you will be given the opportunity to change the online key.

The online key is used to sign all roles except root.

Note: there can be only one online key at a time.
"""

METADATA_SIGNING = """
# Metadata Signing

Metadata signing allows sending signature of pending Repository Service for TUF
(RSTUF) role metadata to an existing RSTUF API deployment.

The Metadata Signing does the following steps:
- retrieves the metadata pending for signatures from RSTUF API
- selects the metadata role for signing
- loads the private key for signing

After loading the key it will sign the role metadata and send the request to
the RSTUF API with the signature.
"""


@admin.group()
@click.pass_context
def metadata(context):
    """
    Metadata management.
    """


def _create_keys_table(
    keys: List[Dict[str, Any]], offline_keys: bool, is_minimal: bool
) -> align.Align:
    """Gets a new keys table."""
    keys_table: table.Table
    if is_minimal:
        keys_table = table.Table(box=box.MINIMAL)
    else:
        keys_table = table.Table()

    keys_table.add_column("Id", justify="center")
    keys_table.add_column("Name/Tag", justify="center")
    keys_table.add_column("Key Type", justify="center")
    keys_table.add_column("Storage", justify="center")
    keys_table.add_column("Public Value", justify="center")

    keys_location: str
    if offline_keys:
        keys_location = "[bright_blue]Offline[/]"
    else:
        keys_location = "[green]Online[/]"

    for key in keys:
        keys_table.add_row(
            f"[yellow]{key['keyid']}",
            text.Text(key["name"], style=Style(color="magenta", bold=True)),
            key["keytype"],
            keys_location,
            f'[yellow]{key["keyval"]["public"]}',
        )

    return align.Align.center(keys_table, vertical="middle")


def _print_md_info_helper(
    table: table.Table,
    keys: List[Dict[str, Any]],
    title: str,
    offline_keys: bool = True,
):
    table.add_row(text.Text(title, style="b cyan", justify="center"))
    pending_keys_table = _create_keys_table(keys, offline_keys, False)
    table.add_row(pending_keys_table)


def _print_md_info(md_info: MetadataInfo, trusted_md: Optional[bool] = True):
    md_table = table.Table()
    md_table.add_column(md_info.type, justify="left", vertical="middle")
    md_table.add_column("KEYS", justify="center", vertical="middle")
    md_keys_table = table.Table(box=box.MINIMAL, show_header=False)

    if not trusted_md:
        # This role is not yet trusted, not all keys were used for signing.
        _print_md_info_helper(md_keys_table, md_info.keys, "\nRoot Key(s)")
        _print_md_info_helper(
            md_keys_table,
            [md_info.online_key],
            "\nOnline Key (used for Timestamp/Snapshot/Target roles)",
            False,
        )
    else:
        keys = md_info.keys
        md_signing_keys_table = _create_keys_table(keys, True, True)
        md_keys_table.add_row(md_signing_keys_table)

    md_table.add_row(
        (
            f"\n{md_info.type} Threshold: [yellow]{md_info.threshold}[/]"
            f"\n{md_info.type} Expiration: [yellow]{md_info.expiration_str}[/]"
            f"\n{md_info.type} Version: [yellow]{md_info.new_root_version}[/]"
        ),
        md_keys_table,
    )

    console.print("\n", md_table)
    console.print("\n")


def _current_md_keys_validation(root_info: MetadataInfo):
    """
    Authorize user by loading a key used for signing the current root metadata.
    """
    console.print(markdown.Markdown(AUTHORIZATION), width=100)
    keys_loaded = 0
    while True:
        root_key: RSTUFKey = load_key_ask_info(Root.type)
        if root_key.error:
            console.print("Failed loading key")
            console.print(root_key.error)
            continue

        if not root_info.is_keyid_used(root_key.key["keyid"]):
            msg = (
                ":cross_mark: [red]Failed[/]: This key has not been used to "
                "sign current root metadata"
            )
            console.print(msg, width=100)
            continue

        root_info.save_current_md_key(root_key)
        keys_loaded += 1
        console.print(f"Key number {keys_loaded} and verified.")
        confirm = prompt.Confirm.ask(
            "Do you want to load another key that will sign the new metadata?"
        )
        if confirm:
            continue

        break

    console.print("\n[green]Authorization is successful[/]\n", width=100)


def _keys_removal(root_info: MetadataInfo):
    """Asking the user if they want to remove any of the root keys"""
    while True:
        if len(root_info.keys) < 1:
            console.print("No keys are left for removal.")
            break

        keys_table = _create_keys_table(root_info.keys, True, False)
        console.print("Here are the current root keys:")
        console.print(keys_table)
        console.print("\n")

        key_removal = prompt.Confirm.ask("Do you want to remove a key")
        if not key_removal:
            break

        name = prompt.Prompt.ask(
            "[green]Name/Tag/ID prefix[/] of the key to remove"
        )
        if not root_info.remove_key(name):
            console.print(
                "\n", f":cross_mark: [red]Failed[/]: key {name} is not in root"
            )
            continue

        console.print(f"Key with name/tag [yellow]{name}[/] removed\n")


def _keys_additions(root_info: MetadataInfo):
    while True:
        keys_table = _create_keys_table(root_info.keys, True, False)
        console.print("\nHere are all keys in the new root:")
        console.print(keys_table)
        keys_needed = root_info.new_keys_required()
        if keys_needed < 1:
            agree = prompt.Confirm.ask("\nDo you want to add a new key?")
            if not agree:
                return
        else:
            console.print(f"\nYou must add {keys_needed} more key(s)\n")

        root_key: RSTUFKey = get_rstuf_key(Root.type)

        if root_key.key["keyid"] == root_info.online_key["keyid"]:
            console.print(
                ":cross_mark: [red]Failed[/]: This is the current online key. "
                "Cannot be added"
            )
            continue

        if root_info.is_keyid_used(root_key.key["keyid"]):
            console.print(":cross_mark: [red]Failed[/]: Key is already used")
            continue

        root_info.add_key(root_key)


def _get_positive_int_input(msg: str, input_name: str, default: Any) -> int:
    input: int = 0
    while True:
        input = prompt.IntPrompt.ask(msg, default=default, show_default=True)
        if input >= 1:
            return input

        console.print(f"{input_name} must be at least 1")


def _modify_expiration(root_info: MetadataInfo):
    console.print(markdown.Markdown(EXPIRY_CHANGES_MSG), width=100)
    console.print("\n")
    change: bool
    while True:
        console.print(
            f"Current root expiration: [cyan]{root_info.expiration_str}[/]",
            highlight=False,  # disable built-in rich highlight
        )
        if root_info.expiration < (datetime.now() + timedelta(days=1)):
            console.print("Root root has expired - expiration must be extend")
            change = True

        else:
            change = prompt.Confirm.ask(
                "Do you want to extend the [cyan]root's expiration[/]?"
            )

        if not change:
            console.print("Skipping root expiration changes")
            return
        else:
            m = "Days to extend [cyan]root's expiration[/] starting from today"
            bump = _get_positive_int_input(m, "Expiration extension", 365)
            new_expiry = datetime.now() + timedelta(days=bump)
            new_exp_str = new_expiry.strftime("%Y-%b-%d")
            agree = prompt.Confirm.ask(
                f"New root expiration: [cyan]{new_exp_str}[/]. Do you agree?"
            )
            if agree:
                root_info.expiration = new_expiry
                return


def _modify_root_keys(root_info: MetadataInfo):
    """Modify root keys"""
    console.print(markdown.Markdown(ROOT_KEYS_CHANGES_MSG), width=100)
    console.print("\n")

    while True:
        change = prompt.Confirm.ask(
            "Do you want to modify [cyan]root[/] keys?"
        )
        if not change:
            console.print("Skipping further root keys changes")
            break

        msg = "\nWhat should be the [cyan]root[/] role [green]threshold?[/]"
        root_info.threshold = _get_positive_int_input(
            msg, "Threshold", root_info.threshold
        )

        console.print(markdown.Markdown(ROOT_KEYS_REMOVAL_MSG), width=100)
        _keys_removal(root_info)

        console.print(markdown.Markdown(ROOT_KEY_ADDITIONS_MSG), width=100)
        _keys_additions(root_info)

        console.print("\nHere is the current content of root:")

        _print_md_info(root_info)


def _modify_online_key(root_info: MetadataInfo):
    console.print(markdown.Markdown(ONLINE_KEY_CHANGE), width=100)
    while True:
        online_key_table = _create_keys_table(
            [root_info.online_key], False, False
        )
        console.print("\nHere is the information for the current online key:")
        console.print("\n")
        console.print(online_key_table)
        console.print("\n")
        change = prompt.Confirm.ask(
            "Do you want to change the [cyan]online key[/]?"
        )
        if not change:
            console.print("Skipping further online key changes")
            break

        online_key: RSTUFKey = get_rstuf_key("ONLINE")

        if online_key.key["keyid"] == root_info.online_key["keyid"]:
            console.print(
                ":cross_mark: [red]Failed[/]: New online key and current match"
            )
            continue

        if root_info.is_keyid_used(online_key.key["keyid"]):
            console.print(
                ":cross_mark: [red]Failed[/]: Key matches one of the root keys"
            )
            continue

        root_info.change_online_key(online_key)


@metadata.command()  # type: ignore
@click.option(
    "--current-root-uri",
    help="URL or local path to the current root.json file.",
    required=False,
)
@click.option(
    "-f",
    "--file",
    "file",
    default="metadata-update-payload.json",
    help="Generate specific JSON payload file",
    show_default=True,
    required=False,
)
@click.option(
    "-u",
    "--upload",
    help=(
        "Upload existent payload 'file'. "
        "Optional '-f/--file' to use non default file name."
    ),
    required=False,
    is_flag=True,
)
@click.option(
    "--run-ceremony",
    help=(
        "When '--upload' is set this flag can be used to run the ceremony "
        "and the result will be uploaded."
    ),
    default=False,
    show_default=True,
    required=False,
    is_flag=True,
)
@click.option(
    "-s",
    "--save",
    help=(
        "Save a copy of the metadata locally. This option saves the JSON "
        "metadata update payload file in the current directory."
    ),
    default=False,
    show_default=True,
    is_flag=True,
)
@click.option(
    "--api-server",
    help="RSTUF API URL i.e.: http://127.0.0.1 .",
    required=False,
)
@click.pass_context
def update(
    context,
    current_root_uri: str,
    file: str,
    upload: bool,
    run_ceremony: bool,
    save: bool,
    api_server: str,
) -> None:
    """
    Start a new metadata update ceremony.
    """
    settings = context.obj["settings"]
    if upload and not run_ceremony:
        # Server configured
        if api_server:
            settings.SERVER = api_server

        if settings.get("SERVER") is None:
            raise click.ClickException(
                "Requires '--api-server' when using '--upload/-u'. "
                "Example: --api-server https://api.rstuf.example.com"
            )

        console.print(
            f"Uploading existing metadata update payload {file} to "
            f"{settings.SERVER}"
        )
        payload = load_payload(file)

        task_id = send_payload(
            settings=settings,
            url=URL.METADATA.value,
            payload=payload,
            expected_msg="Metadata update accepted.",
            command_name="Metadata Update",
        )
        task_status(task_id, settings, "Metadata Update status: ")
        console.print(f"Existing payload {file} sent")

        return

    console.print(markdown.Markdown(INTRODUCTION), width=100)
    if save or not upload:
        console.print(f"\nThis ceremony will generate a new {file} file.")
    console.print("\n")
    NOTICE = (
        "**NOTICE: This is an alpha feature and will get updated over time!**"
    )
    console.print(markdown.Markdown(NOTICE), width=100)
    console.print("\n")

    if current_root_uri is None:
        current_root_uri = prompt.Prompt.ask(
            "[cyan]File name or URL[/] to the current root metadata"
        )
        console.print("\n")
    try:
        root_md: Metadata = get_md_file(current_root_uri)
        root_info: MetadataInfo = MetadataInfo(root_md)
    except StorageError:
        raise click.ClickException(
            f"Cannot fetch/load current root {current_root_uri}"
        )
    except DeserializationError:
        raise click.ClickException("Metadata is invalid JSON file")

    console.print(markdown.Markdown(CURRENT_ROOT_INFO), width=100)

    _print_md_info(root_info)

    _current_md_keys_validation(root_info)

    _modify_expiration(root_info)

    _modify_root_keys(root_info)

    _modify_online_key(root_info)

    console.print(markdown.Markdown("## Payload Generation"))

    if root_info.has_changed():
        # There are one or more changes to the root metadata file.
        payload = root_info.generate_payload()
        # Save if the users asks for it or if the payload won't be uploaded.
        if save or not upload:
            save_payload(file, payload)
            console.print(f"File {file} successfully generated")

        if upload:
            task_id = send_payload(
                settings=settings,
                url=URL.METADATA.value,
                payload=payload,
                expected_msg="Metadata update accepted.",
                command_name="Metadata Update",
            )
            task_status(task_id, settings, "Metadata Update status: ")

        console.print("Ceremony done. 🔐 🎉. Root metadata update completed.")

    else:
        # There are no changes made to the root metadata file.
        console.print("\nNo file will be generated as no changes were made\n")


def _get_pending_and_trusted_roles(
    settings: Any, api_server: Optional[str]
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    if api_server:
        settings.SERVER = api_server

    if settings.get("SERVER") is None:
        api_server = prompt.Prompt.ask("\n[cyan]API[/] URL address")
        settings.SERVER = api_server

    response = request_server(
        settings.SERVER, URL.METADATA_SIGN.value, Methods.GET
    )
    if response.status_code != 200:
        raise click.ClickException(
            f"Failed to retrieve metadata for signing. Error: {response.text}"
        )

    response_data: Dict[str, Any] = response.json().get("data")
    if response_data is None:
        raise click.ClickException(response.text)

    all_roles: Dict[str, Any] = response_data.get("metadata", {})
    if len(all_roles) == 0:
        raise click.ClickException("No metadata available for signing")

    pending_roles: Dict[str, Any] = {}
    trusted_roles: Dict[str, Any] = {}
    for name, role_data in all_roles.items():
        if name.startswith("trusted"):
            trusted_roles[name] = role_data
        else:
            pending_roles[name] = role_data

    return pending_roles, trusted_roles


def _get_pending_signing_keys(
    role_info: MetadataInfo,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    trusted_result = role_info._trusted_md.signed.get_verification_result(
        Root.type,
        role_info._new_md.signed_bytes,
        role_info._new_md.signatures,
    )
    new_result = role_info._new_md.signed.get_verification_result(
        Root.type, role_info._new_md.signed_bytes, role_info._new_md.signatures
    )

    eligible_keyids = trusted_result.unsigned | new_result.unsigned

    new_pending_keys: List[Dict[str, Any]] = []
    trusted_pending_keys: List[Dict[str, Any]] = []
    key: Key
    for keyid in eligible_keyids:
        if keyid in trusted_result.unsigned:
            key = role_info._trusted_md.signed.keys[keyid]
            key_dict = key.to_dict()
            trusted_pending_keys.append(key_dict)
        else:
            # Key coming from new root and not part of trusted root.
            key = role_info._new_md.signed.keys[keyid]
            key_dict = key.to_dict()
            new_pending_keys.append(key_dict)

        # This will also update the key_dict just added in one of the lists.
        key_dict["keyid"] = keyid
        key_dict["name"] = role_info._get_key_name(key)

    return new_pending_keys, trusted_pending_keys


def _print_pending_keys(pending_keys: List[Dict[str, Any]]):
    title = f"Root role still needs {len(pending_keys)} key(s) from any of"
    md_table = table.Table()
    md_table.add_column(
        text.Text(title, style="b cyan", justify="center"),
        justify="center",
        vertical="middle",
    )
    pending_table = _create_keys_table(pending_keys, True, True)
    md_table.add_row(pending_table)
    console.print(md_table)
    console.print("\n")


def _get_signing_key(
    pending_keys: List[Dict[str, Any]], role_info: MetadataInfo
) -> RSTUFKey:
    pending_names = [key_dict["name"] for key_dict in pending_keys]
    while True:
        sign_key_name = prompt.Prompt.ask(
            "\nChoose a private key to load",
            choices=pending_names,
        )
        rstuf_key: RSTUFKey = load_key_ask_info(sign_key_name)
        if rstuf_key.error:
            console.print(rstuf_key.error)
            retry = prompt.Confirm.ask("\nRetry to load a key?")
            if not retry:
                console.print("Aborted.")
                sys.exit(0)
            else:
                continue

        keyid = rstuf_key.key["keyid"]
        if not role_info.is_name_used_in_any_root(keyid, sign_key_name):
            console.print(f"Loaded key is not '{sign_key_name}'")
            continue
        else:
            rstuf_key.name = sign_key_name
            return rstuf_key


def _sign_metadata(role_info: MetadataInfo, rstuf_key: RSTUFKey) -> Signature:
    signer = role_info.get_signer(rstuf_key)
    try:
        signature = role_info._new_md.sign(signer, append=True)
    except UnsignedMetadataError as err:
        raise click.ClickException("Problem signing the metadata") from err

    return signature


@metadata.command()
@click.option(
    "--api-server",
    help="URL to an RSTUF API.",
    required=False,
)
@click.option(
    "--delete",
    help="Delete signing process.",
    required=False,
    is_flag=True,
)
@click.pass_context
def sign(context, api_server: Optional[str], delete: Optional[bool]) -> None:
    """
    Start metadata signature.
    """
    console.print(markdown.Markdown(METADATA_SIGNING), width=100)

    settings = context.obj["settings"]

    pending_roles, trusted_roles = _get_pending_and_trusted_roles(
        settings, api_server
    )
    role_info: MetadataInfo
    rolename: str

    msg: str
    if not delete:
        msg = "sign"
    else:
        msg = "delete signing process"

    while True:
        rolename = prompt.Prompt.ask(
            f"\nChoose a metadata to {msg}",
            choices=[role for role in pending_roles],
        )
        role_info = MetadataInfo(
            Metadata.from_dict(copy.deepcopy(pending_roles[rolename]))
        )
        _print_md_info(role_info, False)
        confirmation = prompt.Confirm.ask(
            f"\nDo you still want to {msg} {rolename}?"
        )
        if confirmation:
            console.print("\n")
            break

    if delete:
        payload = {"role": rolename}
        task_id = send_payload(
            settings,
            URL.METADATA_SIGN_DELETE.value,
            payload,
            "Metadata sign delete accepted.",
            "Metadata delete sign",
        )
        task_status(task_id, settings, "Signing process status: ")
        console.print("\nSigning process deleted!\n")
        return

    trusted_role = trusted_roles.get(f"trusted_{rolename}")
    # If trusted_role is None this means 'rolename' is the first version.
    if trusted_role is not None and len(trusted_role) > 0:
        role_info._trusted_md = Metadata.from_dict(trusted_role)

    new_pending_keys, trusted_pending_keys = _get_pending_signing_keys(
        role_info
    )
    if len(trusted_pending_keys) > 0:
        _print_pending_keys(trusted_pending_keys)

    if len(new_pending_keys) > 0:
        _print_pending_keys(new_pending_keys)

    all_possible_root_keys = trusted_pending_keys + new_pending_keys
    rstuf_key = _get_signing_key(all_possible_root_keys, role_info)
    signature = _sign_metadata(role_info, rstuf_key)

    payload = {"role": rolename, "signature": signature.to_dict()}
    console.print("\nSending signature")
    task_id = send_payload(
        settings,
        URL.METADATA_SIGN.value,
        payload,
        "Metadata sign accepted.",
        "Metadata sign",
    )
    task_status(task_id, settings, "Metadata sign status:")
    console.print("\nMetadata Signed! 🔑\n")
