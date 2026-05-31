from custom_components.sophos_firewall.parser import parse_report_response, pick_top_item


def test_parse_report_response_handles_report_rows_and_totals():
    xml = """
    <Response>
      <Report>
        <Row>
          <Name>Germany</Name>
          <Hits>12</Hits>
          <Bytes>2048</Bytes>
        </Row>
        <Row>
          <Name>United States</Name>
          <Hits>7</Hits>
          <Bytes>1024</Bytes>
        </Row>
      </Report>
    </Response>
    """

    report = parse_report_response(xml)

    assert report.total_hits == 19
    assert report.total_bytes == 3072
    assert report.rows[0].name == "Germany"
    assert report.rows[0].hits == 12
    assert report.rows[0].bytes == 2048


def test_pick_top_item_returns_none_for_empty_rows():
    assert pick_top_item([]) is None
