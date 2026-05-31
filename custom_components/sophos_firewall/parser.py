from __future__ import annotations

from dataclasses import dataclass
import xml.etree.ElementTree as ET


@dataclass(frozen=True, slots=True)
class ReportRow:
    name: str
    hits: int = 0
    bytes: int = 0


@dataclass(frozen=True, slots=True)
class ReportData:
    rows: list[ReportRow]
    total_hits: int
    total_bytes: int


def _strip_namespace(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _text(node: ET.Element | None) -> str | None:
    if node is None or node.text is None:
        return None
    value = node.text.strip()
    return value if value else None


def _child_text_any(node: ET.Element, names: tuple[str, ...]) -> str | None:
    wanted = {name.lower() for name in names}
    for child in list(node):
        if _strip_namespace(child.tag).lower() in wanted:
            value = _text(child)
            if value is not None:
                return value
    return None


def _int(value: str | None) -> int:
    if value is None:
        return 0
    cleaned = value.replace(",", "").strip()
    try:
        return int(float(cleaned))
    except ValueError:
        return 0


def parse_report_response(xml_text: str) -> ReportData:
    """Parse common Sophos/SFOS XML report rows into normalized top-list data."""
    root = ET.fromstring(xml_text)
    rows: list[ReportRow] = []

    for node in root.iter():
        if _strip_namespace(node.tag).lower() not in {"row", "item", "record", "entry"}:
            continue
        name = _child_text_any(node, ("Name", "Key", "Value", "Category", "Country", "Host", "Domain", "Application"))
        if not name:
            continue
        hits = _int(_child_text_any(node, ("Hits", "Count", "Requests", "Packets", "Allowed", "Blocked")))
        byte_count = _int(_child_text_any(node, ("Bytes", "Traffic", "DataTransfer", "Size")))
        rows.append(ReportRow(name=name, hits=hits, bytes=byte_count))

    return ReportData(
        rows=rows,
        total_hits=sum(row.hits for row in rows),
        total_bytes=sum(row.bytes for row in rows),
    )


def pick_top_item(rows: list[ReportRow]) -> ReportRow | None:
    if not rows:
        return None
    return max(rows, key=lambda row: (row.hits, row.bytes, row.name))
