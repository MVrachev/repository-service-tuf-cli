import json

from repository_service_tuf.cli.admin import ceremony
from tests.conftest import _PAYLOADS, _PEMS, invoke_command


class TestCeremony:
    def test_ceremony(self, ceremony_inputs, patch_getpass, patch_utcnow):
        input_step1, input_step2, input_step3, input_step4 = ceremony_inputs
        result = invoke_command(
            ceremony.ceremony,
            input_step1 + input_step2 + input_step3 + input_step4,
            [],
        )

        with open(_PAYLOADS / "ceremony.json") as f:
            expected = json.load(f)

        sigs_r = result.data["metadata"]["root"].pop("signatures")
        sigs_e = expected["metadata"]["root"].pop("signatures")

        assert [s["keyid"] for s in sigs_r] == [s["keyid"] for s in sigs_e]
        assert result.data == expected

    def test_ceremony_threshold_less_than_2(
        self, ceremony_inputs, patch_getpass, patch_utcnow
    ):
        input_step1, _, input_step3, input_step4 = ceremony_inputs
        input_step2 = [  # Configure Root Keys
            "0",  # Please enter root threshold
            "1",  # Please enter root threshold
            "2",  # Please enter root threshold
            f"{_PEMS / 'JC.pub'}",  # Please enter path to public key
            "my rsa key",  # Please enter key name
            "0",  # Please press 0 to add key, or remove key by entering its index  # noqa
            f"{_PEMS / 'JH.pub'}",  # Please enter path to public key
            "JimiHendrix's Key",  # Please enter key name
            "0",  # Please press 0 to add key, or remove key by entering its index.  # noqa
            f"{_PEMS / 'JJ.pub'}",  # Please enter path to public key
            "JanisJoplin's Key",  # Please enter key name
            "1",  # Please press 0 to add key, or remove key by entering its index. Press enter to contiue  # noqa
            "",  # Please press 0 to add key, or remove key by entering its index. Press enter to contiue  # noqa
        ]

        result = invoke_command(
            ceremony.ceremony,
            input_step1 + input_step2 + input_step3 + input_step4,
            [],
        )

        with open(_PAYLOADS / "ceremony.json") as f:
            expected = json.load(f)

        sigs_r = result.data["metadata"]["root"].pop("signatures")
        sigs_e = expected["metadata"]["root"].pop("signatures")

        assert [s["keyid"] for s in sigs_r] == [s["keyid"] for s in sigs_e]
        assert result.data == expected
        assert "Please enter a positive number above 1" in result.stdout

    def test_ceremony_non_positive_expiration(
        self, ceremony_inputs, patch_getpass, patch_utcnow
    ):
        _, input_step2, input_step3, input_step4 = ceremony_inputs
        input_step1 = [  # Configure online role settings and root expiration
            "-1",  # Please enter days until expiry for timestamp role (1)
            "0",  # Please enter days until expiry for timestamp role (1)
            "",  # Please enter days until expiry for timestamp role (1)
            "",  # Please enter days until expiry for snapshot role (1)
            "",  # Please enter days until expiry for targets role (365)
            "",  # Please enter days until expiry for bins role (1)
            "4",  # Please enter number of delegated hash bins [2/4/8/16/32/64/128/256/512/1024/2048/4096/8192/16384] (256)  # noqa
            "",  # Please enter days until expiry for root role (365)
        ]

        result = invoke_command(
            ceremony.ceremony,
            input_step1 + input_step2 + input_step3 + input_step4,
            [],
        )

        with open(_PAYLOADS / "ceremony.json") as f:
            expected = json.load(f)

        sigs_r = result.data["metadata"]["root"].pop("signatures")
        sigs_e = expected["metadata"]["root"].pop("signatures")

        assert [s["keyid"] for s in sigs_r] == [s["keyid"] for s in sigs_e]
        assert result.data == expected
        assert "Please enter a valid positive integer number" in result.stdout

    def test_ceremony_online_key_one_of_root_keys(
        self, ceremony_inputs, patch_getpass, patch_utcnow
    ):
        # Test that online key cannot be one of root key's.
        input_step1, input_step2, _, input_step4 = ceremony_inputs
        input_step3 = [  # Configure Online Key
            f"{_PEMS / 'JH.pub'}",  # Please enter path to public key
            f"{_PEMS / '0d9d3d4bad91c455bc03921daa95774576b86625ac45570d0cac025b08e65043.pub'}",  # Please enter path to public key  # noqa
            "Online Key",  # Please enter a key name
        ]
        result = invoke_command(
            ceremony.ceremony,
            input_step1 + input_step2 + input_step3 + input_step4,
            [],
        )

        with open(_PAYLOADS / "ceremony.json") as f:
            expected = json.load(f)

        sigs_r = result.data["metadata"]["root"].pop("signatures")
        sigs_e = expected["metadata"]["root"].pop("signatures")

        assert [s["keyid"] for s in sigs_r] == [s["keyid"] for s in sigs_e]
        assert result.data == expected
        assert "Key already in use." in result.stdout

    def test_ceremony_try_setting_root_keys_less_than_threshold(
        self, ceremony_inputs, patch_getpass, patch_utcnow
    ):
        input_step1, _, input_step3, input_step4 = ceremony_inputs
        input_step2 = [  # Configure Root Keys
            "2",  # Please enter root threshold
            "0",  # Please press 0 to add key, or remove key by entering its index  # noqa
            f"{_PEMS / 'JH.pub'}",  # Please enter path to public key
            "JimiHendrix's Key",  # Please enter key name
            # Try continuing even though threshold is not reached.
            "",  # Please press 0 to add key, or remove key by entering its index.  # noqa
            "0",  # Please press 0 to add key, or remove key by entering its index. # noqa
            f"{_PEMS / 'JJ.pub'}",  # Please enter path to public key
            "JanisJoplin's Key",  # Please enter key name
            "",  # Please press 0 to add key, or remove key by entering its index. Press enter to contiue  # noqa
        ]
        result = invoke_command(
            ceremony.ceremony,
            input_step1 + input_step2 + input_step3 + input_step4,
            [],
        )

        with open(_PAYLOADS / "ceremony.json") as f:
            expected = json.load(f)

        sigs_r = result.data["metadata"]["root"].pop("signatures")
        sigs_e = expected["metadata"]["root"].pop("signatures")

        assert [s["keyid"] for s in sigs_r] == [s["keyid"] for s in sigs_e]
        assert result.data == expected
        # Asser that at least root_threshold number of public keys are added.
        root_role = result.data["metadata"]["root"]["signed"]["roles"]["root"]
        assert len(root_role["keyids"]) <= root_role["threshold"]
