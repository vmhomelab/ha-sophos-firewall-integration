from __future__ import annotations

from datetime import timedelta
import logging

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .const import DEFAULT_UPDATE_INTERVAL, DOMAIN
from .parser import ResourceData
from .sophos_client import RESOURCE_DEFINITIONS, SophosFirewallClient

_LOGGER = logging.getLogger(__name__)


EMPTY_RESOURCE = ResourceData(items=[])


class SophosFirewallCoordinator(DataUpdateCoordinator):
    def __init__(self, hass: HomeAssistant, client: SophosFirewallClient, update_interval: int = DEFAULT_UPDATE_INTERVAL) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=update_interval),
        )
        self.client = client
        self.last_errors: dict[str, str] = {}

    async def _fetch_resource_safely(self, resource_key: str) -> tuple[str, ResourceData | None, str | None]:
        try:
            _LOGGER.debug("Fetching Sophos resource %s", resource_key)
            resource = await self.client.fetch_resource(resource_key)
        except Exception as exc:  # noqa: BLE001 - expose a sanitized HA warning and keep other sensors alive
            message = f"{type(exc).__name__}: {exc}"
            _LOGGER.warning("Failed to fetch Sophos resource %s: %s", resource_key, message)
            return resource_key, None, message

        _LOGGER.debug("Fetched Sophos resource %s: count=%d", resource_key, resource.count)
        return resource_key, resource, None

    async def _async_update_data(self):
        results = []
        for definition in RESOURCE_DEFINITIONS:
            results.append(await self._fetch_resource_safely(definition.key))

        data: dict[str, ResourceData] = {}
        errors: dict[str, str] = {}
        for resource_key, resource, error in results:
            if resource is None:
                errors[resource_key] = error or "Unknown error"
                data[resource_key] = self.data.get(resource_key, EMPTY_RESOURCE) if self.data else EMPTY_RESOURCE
            else:
                data[resource_key] = resource

        self.last_errors = errors
        if errors:
            _LOGGER.info("Sophos resource update completed with %d failed resource(s)", len(errors))

        return data
