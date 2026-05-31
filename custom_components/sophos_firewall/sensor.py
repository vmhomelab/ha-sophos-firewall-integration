from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from homeassistant.components.sensor import SensorEntity, SensorEntityDescription
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import UnitOfInformation
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .parser import pick_top_item


@dataclass(frozen=True, kw_only=True)
class SophosSensorDescription(SensorEntityDescription):
    report_key: str
    mode: str = "top_name"


SENSORS: tuple[SophosSensorDescription, ...] = (
    SophosSensorDescription(key="blocked_traffic", name="Sophos Blocked Traffic", report_key="blocked_traffic", mode="total_hits"),
    SophosSensorDescription(key="allowed_traffic", name="Sophos Allowed Traffic", report_key="allowed_traffic", mode="total_hits"),
    SophosSensorDescription(key="allowed_application_categories", name="Sophos Top Allowed Application Category", report_key="allowed_application_categories"),
    SophosSensorDescription(key="allowed_web_categories", name="Sophos Top Allowed Web Category", report_key="allowed_web_categories"),
    SophosSensorDescription(key="source_countries", name="Sophos Top Source Country", report_key="source_countries"),
    SophosSensorDescription(key="destination_countries", name="Sophos Top Destination Country", report_key="destination_countries"),
    SophosSensorDescription(key="web_domains", name="Sophos Top Web Domain", report_key="web_domains"),
    SophosSensorDescription(key="top_hosts", name="Sophos Top Host", report_key="top_hosts"),
)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback) -> None:
    coordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(SophosFirewallSensor(coordinator, entry, description) for description in SENSORS)


class SophosFirewallSensor(CoordinatorEntity, SensorEntity):
    entity_description: SophosSensorDescription

    def __init__(self, coordinator, entry: ConfigEntry, description: SophosSensorDescription) -> None:
        super().__init__(coordinator)
        self.entity_description = description
        self._attr_unique_id = f"{entry.entry_id}_{description.key}"
        self._attr_device_info = {
            "identifiers": {(DOMAIN, entry.entry_id)},
            "name": "Sophos Firewall",
            "manufacturer": "Sophos",
        }

    @property
    def native_value(self) -> str | int | None:
        report = self.coordinator.data.get(self.entity_description.report_key) if self.coordinator.data else None
        if report is None:
            return None
        if self.entity_description.mode == "total_hits":
            return report.total_hits
        top = pick_top_item(report.rows)
        return top.name if top else None

    @property
    def native_unit_of_measurement(self) -> str | None:
        if self.entity_description.mode == "total_hits":
            return "requests"
        return None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        report = self.coordinator.data.get(self.entity_description.report_key) if self.coordinator.data else None
        if report is None:
            return {}
        rows = [{"name": row.name, "hits": row.hits, "bytes": row.bytes} for row in report.rows[:10]]
        return {
            "total_hits": report.total_hits,
            "total_bytes": report.total_bytes,
            "top": rows,
        }
