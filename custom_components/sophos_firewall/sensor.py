from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from homeassistant.components.sensor import SensorEntity, SensorEntityDescription
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .parser import pick_first_item, resource_attributes


@dataclass(frozen=True, kw_only=True)
class SophosSensorDescription(SensorEntityDescription):
    resource_key: str
    mode: str = "count"


SENSORS: tuple[SophosSensorDescription, ...] = (
    SophosSensorDescription(key="firewall_rules", name="Sophos Firewall Rules", resource_key="firewall_rules"),
    SophosSensorDescription(key="firewall_rule_groups", name="Sophos Firewall Rule Groups", resource_key="firewall_rule_groups"),
    SophosSensorDescription(key="nat_rules", name="Sophos NAT Rules", resource_key="nat_rules"),
    SophosSensorDescription(key="ssl_tls_inspection_rules", name="Sophos SSL TLS Inspection Rules", resource_key="ssl_tls_inspection_rules"),
    SophosSensorDescription(key="web_filter_exceptions", name="Sophos Web Filter Exceptions", resource_key="web_filter_exceptions"),
    SophosSensorDescription(key="interfaces", name="Sophos Interfaces", resource_key="interfaces"),
    SophosSensorDescription(key="ip_hosts", name="Sophos IP Hosts", resource_key="ip_hosts"),
    SophosSensorDescription(key="fqdn_hosts", name="Sophos FQDN Hosts", resource_key="fqdn_hosts"),
    SophosSensorDescription(key="mac_hosts", name="Sophos MAC Hosts", resource_key="mac_hosts"),
    SophosSensorDescription(key="services", name="Sophos Services", resource_key="services"),
    SophosSensorDescription(key="local_service_acl_rules", name="Sophos Local Service ACL Rules", resource_key="local_service_acl_rules"),
    SophosSensorDescription(key="schedules", name="Sophos Schedules", resource_key="schedules"),
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
        self._attr_native_unit_of_measurement = "objects"
        self._attr_device_info = {
            "identifiers": {(DOMAIN, entry.entry_id)},
            "name": "Sophos Firewall",
            "manufacturer": "Sophos",
        }

    @property
    def native_value(self) -> str | int | None:
        resource = self.coordinator.data.get(self.entity_description.resource_key) if self.coordinator.data else None
        if resource is None:
            return None
        if self.entity_description.mode == "first_name":
            first = pick_first_item(resource.items)
            return first.name if first else None
        return resource.count

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        resource = self.coordinator.data.get(self.entity_description.resource_key) if self.coordinator.data else None
        if resource is None:
            return {}
        attributes = resource_attributes(resource)
        last_error = getattr(self.coordinator, "last_errors", {}).get(self.entity_description.resource_key)
        if last_error:
            attributes["last_error"] = last_error
        return attributes
