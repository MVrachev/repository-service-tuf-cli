import json

import pretend

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

    def test_ceremony_api_server_no_bootstrap(self, ceremony_inputs):
        input_step1, input_step2, input_step3, input_step4 = ceremony_inputs
        args = ["--api-server", "http://localhost:80"]
        result = invoke_command(
            ceremony.ceremony,
            input_step1 + input_step2 + input_step3 + input_step4,
            args,
            std_err_empty=False,
        )

        err = "Not allowed using '--api-server' without '--bootstrap'"
        assert err in result.stderr

    def test_ceremony_bootstrap_no_api_server_no_settings(
        self, ceremony_inputs
    ):
        input_step1, input_step2, input_step3, input_step4 = ceremony_inputs
        args = ["--bootstrap"]
        result = invoke_command(
            ceremony.ceremony,
            input_step1 + input_step2 + input_step3 + input_step4,
            args,
            std_err_empty=False,
        )

        err = "Requires '--api-server'"
        assert err in result.stderr

    def test_ceremony_bootstrap_api_server_locked_for_bootstrap(
        self, ceremony_inputs, monkeypatch
    ):
        status = {
            "data": {"bootstrap": True},
            "message": "Locked for bootstrap",
        }
        fake_bootstrap_status = pretend.call_recorder(lambda a: status)
        monkeypatch.setattr(
            ceremony, "bootstrap_status", fake_bootstrap_status
        )
        input_step1, input_step2, input_step3, input_step4 = ceremony_inputs
        args = ["--bootstrap", "--api-server", "http://localhost"]

        result = invoke_command(
            ceremony.ceremony,
            input_step1 + input_step2 + input_step3 + input_step4,
            args,
            std_err_empty=False,
        )

        assert status["message"] in result.stderr
        assert fake_bootstrap_status.calls == [
            pretend.call(result.context["settings"])
        ]

    def test_ceremony_bootstrap_bootstrap_no_api_server_with_settings_server(
        self,
        ceremony_inputs,
        test_context,
        monkeypatch,
        patch_getpass,
        patch_utcnow,
    ):
        server = "http://localhost:80"
        test_context["settings"].SERVER = server
        status = {"data": {"bootstrap": False}}
        fake_bootstrap_status = pretend.call_recorder(lambda a: status)
        monkeypatch.setattr(
            ceremony, "bootstrap_status", fake_bootstrap_status
        )
        fake_task_id = "123ab"
        fake_send_payload = pretend.call_recorder(lambda **kw: fake_task_id)
        monkeypatch.setattr(ceremony, "send_payload", fake_send_payload)
        fake_task_status = pretend.call_recorder(lambda *a: None)
        monkeypatch.setattr(ceremony, "task_status", fake_task_status)
        input_step1, input_step2, input_step3, input_step4 = ceremony_inputs
        args = ["--bootstrap"]

        invoke_command(
            ceremony.ceremony,
            input_step1 + input_step2 + input_step3 + input_step4,
            args,
            test_context=test_context,
        )

        with open(_PAYLOADS / "ceremony.json") as f:
            expected = json.load(f)

        assert fake_bootstrap_status.calls == [
            pretend.call(test_context["settings"])
        ]
        call = fake_send_payload.calls[0]
        # This particular key with id "50d7e110ad65f3b2dba5c3cfc8c5ca259be9774cc26be3410044ffd4be3aa5f3"  # noqa
        # is ecdsa type meaning it's not deterministic. It's expected to be
        # different than expected that's why just equalize them.
        expected["metadata"]["root"]["signatures"][1]["sig"] = call.kwargs[
            "payload"
        ]["metadata"]["root"]["signatures"][1]["sig"]
        assert fake_send_payload.calls == [
            pretend.call(
                settings=test_context["settings"],
                url=ceremony.URL.BOOTSTRAP.value,
                payload=expected,
                expected_msg="Bootstrap accepted.",
                command_name="Bootstrap",
            )
        ]
        assert fake_task_status.calls == [
            pretend.call(
                fake_task_id, test_context["settings"], "Bootstrap status: "
            )
        ]

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
