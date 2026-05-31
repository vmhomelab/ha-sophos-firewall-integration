from __future__ import annotations

from typing import Any

from .const import (
    CONF_REQUEST_TIMEOUT,
    CONF_UPDATE_INTERVAL,
    CONF_VERIFY_SSL,
    DEFAULT_REQUEST_TIMEOUT,
    DOMAIN,
    MAX_REQUEST_TIMEOUT,
    PLATFORMS,
)
from .sophos_client import SophosFirewallClient


async def async_setup_entry(hass: Any, entry: Any) -> bool:
    from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME

    from .coordinator import SophosFirewallCoordinator

    client = SophosFirewallClient(
        host=entry.data[CONF_HOST],
        username=entry.data[CONF_USERNAME],
        password=entry.data[CONF_PASSWORD],
        verify_ssl=entry.data.get(CONF_VERIFY_SSL, False),
        timeout=min(
            entry.data.get(CONF_REQUEST_TIMEOUT, DEFAULT_REQUEST_TIMEOUT),
            MAX_REQUEST_TIMEOUT,
        ),
    )
    coordinator = SophosFirewallCoordinator(
        hass,
        client,
        update_interval=entry.data.get(CONF_UPDATE_INTERVAL, 300),
    )
    await coordinator.async_config_entry_first_refresh()

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: Any, entry: Any) -> bool:
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id)
    return unload_ok
