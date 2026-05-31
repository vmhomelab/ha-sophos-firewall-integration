from __future__ import annotations

from datetime import timedelta
import logging

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import DEFAULT_UPDATE_INTERVAL, DOMAIN
from .sophos_client import REPORT_PAYLOADS, SophosFirewallClient

_LOGGER = logging.getLogger(__name__)


class SophosFirewallCoordinator(DataUpdateCoordinator):
    def __init__(self, hass: HomeAssistant, client: SophosFirewallClient, update_interval: int = DEFAULT_UPDATE_INTERVAL) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=update_interval),
        )
        self.client = client

    async def _async_update_data(self):
        data = {}
        for report_key in REPORT_PAYLOADS:
            try:
                data[report_key] = await self.client.fetch_report(report_key)
            except Exception as exc:  # noqa: BLE001 - Home Assistant surfaces UpdateFailed safely
                raise UpdateFailed(f"Failed to fetch Sophos report {report_key}: {exc}") from exc
        return data
