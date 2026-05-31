import pytest

from custom_components.sophos_firewall.sophos_client import SophosFirewallClient, _response_status


def test_client_trims_host_and_uses_api_controller_path():
    client = SophosFirewallClient("https://firewall.example:4444/", "user", "pass")

    assert client.api_url == "https://firewall.example:4444/webconsole/APIController"


def test_client_normalizes_plain_host_to_sfos_admin_api_port():
    client = SophosFirewallClient("10.17.1.1", "user", "pass")

    assert client.api_url == "https://10.17.1.1:4444/webconsole/APIController"


def test_client_normalizes_missing_port_to_sfos_admin_api_port():
    client = SophosFirewallClient("http://10.17.1.1", "user", "pass")

    assert client.api_url == "https://10.17.1.1:4444/webconsole/APIController"


def test_client_default_timeout_stays_below_home_assistant_slow_update_warning():
    client = SophosFirewallClient("https://firewall.example:4444", "user", "pass")

    assert client.timeout == 8
    assert client.http_timeout.connect is not None
    assert client.http_timeout.connect <= 5


@pytest.mark.parametrize(
    ("xml", "status"),
    [
        ("<Response><Login><status>Authentication Failure</status></Login></Response>", "Authentication Failure"),
        ("<Response><Status>Configuration applied successfully.</Status></Response>", "Configuration applied successfully."),
    ],
)
def test_response_status_extracts_sfos_status_text(xml, status):
    assert _response_status(xml) == status
