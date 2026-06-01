from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import xml.etree.ElementTree as ET


@dataclass(frozen=True, slots=True)
class ResourceItem:
    name: str
    attributes: dict[str, str]


@dataclass(frozen=True, slots=True)
class ResourceData:
    items: list[ResourceItem]

    @property
    def count(self) -> int:
        return len(self.items)


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


def _direct_text_attributes(node: ET.Element) -> dict[str, str]:
    attributes: dict[str, str] = {}
    for child in list(node):
        tag = _strip_namespace(child.tag)
        value = _text(child)
        if value is not None:
            attributes[tag] = value
    return attributes


def parse_resource_response(xml_text: str, resource_tag: str) -> ResourceData:
    """Parse an official SFOS XML API Get response for one resource type.

    The Sophos Postman collection exposes configuration resources such as
    FirewallRule, NATRule, Interface, IPHost, Services, etc. These are not
    report rows; each matching XML element is one configured object.
    """
    root = ET.fromstring(xml_text)
    wanted = resource_tag.lower()
    items: list[ResourceItem] = []

    for node in root.iter():
        if _strip_namespace(node.tag).lower() != wanted:
            continue

        name = _child_text_any(node, ("Name", "RuleName", "HostName", "Description"))
        if not name:
            name = f"{resource_tag} #{len(items) + 1}"

        items.append(ResourceItem(name=name, attributes=_direct_text_attributes(node)))

    return ResourceData(items=items)


def pick_first_item(items: list[ResourceItem]) -> ResourceItem | None:
    if not items:
        return None
    return sorted(items, key=lambda item: item.name.casefold())[0]


def resource_attributes(data: ResourceData, limit: int = 10) -> dict[str, Any]:
    return {
        "count": data.count,
        "items": [
            {
                "name": item.name,
                "attributes": item.attributes,
            }
            for item in data.items[:limit]
        ],
    }
