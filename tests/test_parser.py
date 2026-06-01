from custom_components.sophos_firewall.parser import parse_resource_response, pick_first_item, resource_attributes


def test_parse_resource_response_counts_official_sfos_objects():
    xml = """
    <Response>
      <Login><status>Authentication Successful</status></Login>
      <FirewallRule transactionid="1">
        <Name>LAN to WAN</Name>
        <Status>Enable</Status>
        <IPFamily>IPv4</IPFamily>
      </FirewallRule>
      <FirewallRule transactionid="2">
        <Name>Block Guest</Name>
        <Status>Disable</Status>
        <IPFamily>IPv4</IPFamily>
      </FirewallRule>
    </Response>
    """

    resource = parse_resource_response(xml, "FirewallRule")

    assert resource.count == 2
    assert resource.items[0].name == "LAN to WAN"
    assert resource.items[0].attributes["Status"] == "Enable"
    assert resource.items[1].attributes["IPFamily"] == "IPv4"


def test_parse_resource_response_uses_fallback_name_for_unnamed_objects():
    xml = """
    <Response>
      <LocalServiceACL>
        <SourceZone>LAN</SourceZone>
        <Service>HTTPS</Service>
      </LocalServiceACL>
    </Response>
    """

    resource = parse_resource_response(xml, "LocalServiceACL")

    assert resource.count == 1
    assert resource.items[0].name == "LocalServiceACL #1"


def test_pick_first_item_returns_none_for_empty_items():
    assert pick_first_item([]) is None


def test_resource_attributes_limits_items_and_includes_count():
    xml = """
    <Response>
      <Interface><Name>Port1</Name></Interface>
      <Interface><Name>Port2</Name></Interface>
    </Response>
    """

    resource = parse_resource_response(xml, "Interface")
    attrs = resource_attributes(resource, limit=1)

    assert attrs["count"] == 2
    assert attrs["items"] == [{"name": "Port1", "attributes": {"Name": "Port1"}}]
