# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Literal, Optional

from securesystemslib.signer import Signer, SSlibSigner  # type: ignore
from tuf.api.metadata import (
    SPECIFICATION_VERSION,
    TOP_LEVEL_ROLE_NAMES,
    Key,
    Metadata,
    Role,
    Root,
    Timestamp,
)
from tuf.api.serialization.json import JSONSerializer

SPEC_VERSION: str = ".".join(SPECIFICATION_VERSION)
BINS: str = "bins"


repository_metadata: Dict[str, Metadata] = {}


class Roles(Enum):
    ROOT = "root"
    TARGETS = "targets"
    SNAPSHOT = "snapshot"
    TIMESTAMP = "timestamp"
    BINS = "bins"


@dataclass
class ServiceSettings:
    number_of_delegated_bins: int = 256
    targets_base_url: str = ""
    targets_online_key: bool = True

    def to_dict(self):
        return asdict(self)


@dataclass
class RSTUFKey:
    key: Optional[dict] = field(default_factory=dict)
    key_path: Optional[str] = None
    error: Optional[str] = None


@dataclass
class BootstrapSetup:
    expiration: Dict[Roles, int]
    services: ServiceSettings
    number_of_keys: Dict[Literal[Roles.ROOT, Roles.TARGETS], int]
    threshold: Dict[Literal[Roles.ROOT, Roles.TARGETS], int]
    keys: Dict[Roles, List[RSTUFKey]] = field(default_factory=dict)
    online_key: RSTUFKey = field(default_factory=RSTUFKey)

    def to_dict(self):
        return {
            "expiration": {k.value: v for k, v in self.expiration.items()},
            "services": self.services.to_dict(),
        }


def initialize_metadata(
    setup: BootstrapSetup, save=True
) -> Dict[str, Metadata]:
    """
    Creates TUF top-level root role metadata.
    """
    def _signers(role: Roles) -> List[Signer]:
        """Returns all Signers from the settings for a specific role name"""
        return [SSlibSigner(key.key) for key in setup.keys[role]]

    def _sign(role: Metadata, role_name: str) -> None:
        """Re-signs metadata with role-specific key from global key store.
        The metadata role type is used as default key id. This is only allowed
        for top-level roles.
        """
        role.signatures.clear()
        for signer in _signers(Roles[role_name.upper()]):
            role.sign(signer, append=True)

    def _add_payload(role: Metadata, role_name: str) -> None:
        """Persists metadata using the configured storage backend.
        The metadata role type is used as default role name. This is only
        allowed for top-level roles.
        """
        filename = f"{role_name}"

        if role_name != Timestamp.type:
            filename = f"{role.signed.version}.{filename}"

        repository_metadata[filename] = role

        if save:
            role.to_file(f"metadata/{filename}.json", JSONSerializer())

    def _bump_expiry(role: Metadata, role_name: str) -> None:
        """Bumps metadata expiration date by role-specific interval.
        The metadata role type is used as default expiry id. This is only
        allowed for top-level roles.
        """
        # FIXME: Review calls to _bump_expiry. Currently, it is called in
        # every update-sign-persist cycle.
        # PEP 458 is unspecific about when to bump expiration, e.g. in the
        # course of a consistent snapshot only 'timestamp' is bumped:
        # https://www.python.org/dev/peps/pep-0458/#producing-consistent-snapshots
        role.signed.expires = datetime.now().replace(
            microsecond=0
        ) + timedelta(days=setup.expiration[Roles[role_name.upper()]])

    # Populate public key store, and define trusted signing keys and required
    # signature thresholds for each top-level role in 'root'.
    roles: dict[str, Role] = {}
    add_key_args: list[tuple[Key, str]] = []
    for role_name in TOP_LEVEL_ROLE_NAMES:
        if role_name == Roles.ROOT.value:
            threshold = setup.threshold[Roles.ROOT]
        else:
            threshold = 1

        signers = _signers(Roles[role_name.upper()])

        # FIXME: Is this a meaningful check? Should we check more than just
        # the threshold? And maybe in a different place, e.g. independently of
        # bootstrapping the metadata, because in production we do not have
        # access to all top-level role signing keys at the time of
        # bootstrapping the metadata.
        if len(signers) < threshold:
            raise ValueError(
                f"not enough keys ({len(signers)}) for "
                f"signing threshold '{threshold}'"
            )

        roles[role_name] = Role([], threshold)
        for signer in signers:
            add_key_args.append(
                (Key.from_securesystemslib_key(signer.key_dict), role_name)
            )

    # Add signature wrapper, bump expiration, sign and persist the root role.
    # Bootstrap default top-level metadata to be updated below if necessary
    root_metadata = Metadata(Root(roles=roles))
    for arg in add_key_args:
        root_metadata.signed.add_key(arg[0], arg[1])

    metadata_type = root_metadata.signed.type
    _bump_expiry(root_metadata, metadata_type)
    _sign(root_metadata, metadata_type)
    _add_payload(root_metadata, metadata_type)

    return repository_metadata
