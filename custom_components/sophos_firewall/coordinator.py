from __future__ import annotations

import asyncio
from datetime import timedelta
import logging

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .const import DEFAULT_UPDATE_INTERVAL, DOMAIN
from .parser import ReportData
from .sophos_client import REPORT_PAYLOADS, SophosFirewallClient

_LOGGER = logging.getLogger(__name__)


EMPTY_REPORT = ReportData(rows=[], total_hits=0, total_bytes=0)


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

    async def _fetch_report_safely(self, report_key: str) -> tuple[str, ReportData | None, str | None]:
        try:
            _LOGGER.debug("Fetching Sophos report %s", report_key)
            report = await self.client.fetch_report(report_key)
        except Exception as exc:  # noqa: BLE001 - expose a sanitized HA warning and keep other sensors alive
            message = f"{type(exc).__name__}: {exc}"
            _LOGGER.warning("Failed to fetch Sophos report %s: %s", report_key, message)
            return report_key, None, message

        _LOGGER.debug(
            "Fetched Sophos report %s: rows=%d total_hits=%d total_bytes=%d",
            report_key,
            len(report.rows),
            report.total_hits,
            report.total_bytes,
        )
        return report_key, report, None

    async def _async_update_data(self):
        results = await asyncio.gather(
            *(self._fetch_report_safely(report_key) for report_key in REPORT_PAYLOADS),
        )

        data: dict[str, ReportData] = {}
        errors: dict[str, str] = {}
        for report_key, report, error in results:
            if report is None:
                errors[report_key] = error or "Unknown error"
                data[report_key] = self.data.get(report_key, EMPTY_REPORT) if self.data else EMPTY_REPORT
            else:
                data[report_key] = report

        self.last_errors = errors
        if errors:
            _LOGGER.info("Sophos report update completed with %d failed report(s)", len(errors))

        return data
