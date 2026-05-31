from custom_components.sophos_firewall.sophos_client import SophosFirewallClient


def test_client_trims_host_and_uses_api_controller_path():
    client = SophosFirewallClient("https://firewall.example:4444/", "user", "pass")

    assert client.api_url == "https://firewall.example:4444/webconsole/APIController"


def test_client_default_timeout_stays_below_home_assistant_slow_update_warning():
    client = SophosFirewallClient("https://firewall.example:4444", "user", "pass")

    assert client.timeout == 8
    assert client.http_timeout.connect is not None
    assert client.http_timeout.connect <= 5
