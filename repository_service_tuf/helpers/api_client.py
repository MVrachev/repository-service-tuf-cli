# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT
import json
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional

import requests
import rich_click as click
from dynaconf import LazySettings
from requests.exceptions import ConnectionError
from rich.console import Console
from tuf.api.metadata import Metadata

console = Console()


class URL(Enum):
    token = "api/v1/token/"  # nosec bandit: not hard coded password.
    bootstrap = "api/v1/bootstrap/"
    config = "api/v1/config/"
    metadata="api/v1/metadata/"
    task = "api/v1/task/?task_id="
    publish_targets = "api/v1/targets/publish/"


class Methods(Enum):
    get = "get"
    post = "post"


@dataclass
class Login:
    state: bool
    data: Optional[Dict[str, Any]] = None


def request_server(
    server: str,
    url: str,
    method: Methods,
    payload: Optional[Dict[str, Any]] = None,
    data: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
) -> requests.Response:
    try:
        if method == Methods.get:
            response = requests.get(
                f"{server}/{url}", json=payload, data=data, headers=headers
            )

        elif method == Methods.post:
            response = requests.post(
                f"{server}/{url}", json=payload, data=data, headers=headers
            )

        else:
            raise ValueError("Internal Error. Invalid HTTP/S Method.")

    except ConnectionError:
        raise click.ClickException(f"Failed to connect to {server}")

    return response


def is_logged(settings: LazySettings):
    if settings.get("AUTH") is False:
        return None

    token = settings.get("TOKEN")
    server = settings.get("SERVER")
    headers = {"Authorization": f"Bearer {token}"}

    url = f"{URL.token.value}?token={token}"
    response = request_server(server, url, Methods.get, headers=headers)
    if response.status_code == 401 or response.status_code == 403:
        return Login(state=False)

    elif response.status_code == 200:
        data = response.json().get("data", {})
        if data.get("expired") is False:
            return Login(state=True, data=data)

    else:
        raise click.ClickException(
            f"Error {response.status_code} {response.text}"
        )


def get_headers(settings: LazySettings) -> Dict[str, str]:
    if settings.get("AUTH") is False:
        return {}

    server = settings.get("SERVER")
    token = settings.get("TOKEN")
    if server and token:
        token_access_check = is_logged(settings)
        if token_access_check.state is False:
            raise click.ClickException(
                f"{str(token_access_check.data)}"
                "\n\nTry re-login: 'rstuf admin login'"
            )

        expired_admin = token_access_check.data.get("expired")
        if expired_admin is True:
            raise click.ClickException(
                "The token has expired. Run 'rstuf admin login'"
            )
        else:
            headers = {"Authorization": f"Bearer {token}"}
            response = request_server(
                server, URL.bootstrap.value, Methods.get, headers=headers
            )
            if response.status_code != 200:
                raise click.ClickException(
                    f"Unexpected error: {response.text}"
                )
    else:
        raise click.ClickException("Login first. Run 'rstuf admin login'")

    return headers


def bootstrap_status(settings: LazySettings) -> Dict[str, Any]:
    headers = get_headers(settings)
    response = request_server(
        settings.SERVER, URL.bootstrap.value, Methods.get, headers=headers
    )
    if response.status_code == 404:
        raise click.ClickException(
            f"Server {settings.SERVER} does not allow bootstrap"
        )
    if response.status_code != 200:
        raise click.ClickException(
            f"Error {response.status_code} {response.text}"
        )

    bootstrap_json = response.json()
    if bootstrap_json is None:
        raise click.ClickException(f"Unexpected error {response.text}")

    return bootstrap_json


def task_status(
    task_id: str, settings: LazySettings, title: Optional[str]
) -> Dict[str, Any]:
    headers = get_headers(settings)
    received_states = []
    while True:
        state_response = request_server(
            settings.SERVER,
            f"{URL.task.value}{task_id}",
            Methods.get,
            headers=headers,
        )

        if state_response.status_code != 200:
            raise click.ClickException(
                f"Unexpected response {state_response.text}"
            )

        data = state_response.json().get("data")

        if data:
            if state := data.get("state"):
                if state not in received_states:
                    console.print(f"{title}{state}")
                    received_states.append(state)
                else:
                    console.print(".", end="")

                if state == "SUCCESS":
                    return data

                elif state == "FAILURE":
                    raise click.ClickException(
                        f"Failed: {state_response.text}"
                    )

            else:
                raise click.ClickException(
                    f"No state in data received {state_response.text}"
                )
        else:
            raise click.ClickException(
                f"No data received {state_response.text}"
            )
        time.sleep(2)


def publish_targets(settings: LazySettings) -> str:
    headers = get_headers(settings)
    publish_targets = request_server(
        settings.SERVER,
        URL.publish_targets.value,
        Methods.post,
        headers=headers,
    )
    if publish_targets.status_code != 202:
        raise click.ClickException(
            f"Failed to publish targets. {publish_targets.status_code} "
            f"{publish_targets.text}"
        )
    task_id = publish_targets.json()["data"]["task_id"]

    return task_id


def send_payload(
    settings: LazySettings,
    url: str,
    method: Methods,
    payload: Dict[str, Any],
    expected_msg: str,
    command_name: str,
) -> str:
    """
    Send 'payload' to a given 'settings.SERVER'.

    Args:
        settings: the command context settings object
        url: one of the URLs to a given endpoint as defined in api_client.py
        method: REST API method to use as defined in api_client.py
        payload: dictionary containing the payload to send
        expected_msg: expected message to receive as a response to the request
        command_name: name of the command sending the payload, used for logging

    Returns:
        Task id of the job sending the payload.
    """
    headers = get_headers(settings)
    response = request_server(
        settings.SERVER,
        url,
        method,
        payload,
        headers=headers,
    )

    if response.status_code != 202:
        raise click.ClickException(
            f"Error {response.status_code} {response.text}"
        )

    response_json = response.json()
    if (
        response_json.get("message") is None
        or response_json.get("message") != expected_msg
    ):
        raise click.ClickException(response.text)

    else:
        if data := response_json.get("data"):
            task_id = data.get("task_id")
            if task_id is None:
                raise click.ClickException(
                    f"Failed to get `task id` {response.text}"
                )
            console.print(f"{command_name} status: ACCEPTED ({task_id})")

            return task_id
        else:
            raise click.ClickException(
                f"Failed to get task response data {response.text}"
            )


def get_md_file(file_uri: str) -> Metadata:
    parsed_url = file_uri.split("://")
    protocol = parsed_url[0]
    role_md: Metadata
    if protocol in ["http", "https"]:
        console.print(f"Fetching file {file_uri}")
        base_url = f"{parsed_url[1].split('/')[0]}"
        server = f"{protocol}://{base_url}"
        url = "".join(parsed_url[1].split("/")[1:])
        response = request_server(server, url, Methods.get)
        if response.status_code != 200:
            raise click.ClickException(f"Cannot fetch {file_uri}")
        json_data = json.loads(response.text)
        role_md = Metadata.from_dict(json_data)
    else:
        role_md = Metadata.from_file(file_uri)

    return role_md
