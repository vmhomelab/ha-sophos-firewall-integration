from __future__ import annotations

from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME
from homeassistant.data_entry_flow import FlowResult

from .const import (
    CONF_REQUEST_TIMEOUT,
    CONF_UPDATE_INTERVAL,
    CONF_VERIFY_SSL,
    DEFAULT_REQUEST_TIMEOUT,
    DEFAULT_UPDATE_INTERVAL,
    DEFAULT_VERIFY_SSL,
    DOMAIN,
)


class SophosFirewallConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            await self.async_set_unique_id(user_input[CONF_HOST].rstrip("/"))
            self._abort_if_unique_id_configured()
            return self.async_create_entry(title="Sophos Firewall", data=user_input)

        schema = vol.Schema(
            {
                vol.Required(CONF_HOST): str,
                vol.Required(CONF_USERNAME): str,
                vol.Required(CONF_PASSWORD): str,
                vol.Optional(CONF_VERIFY_SSL, default=DEFAULT_VERIFY_SSL): bool,
                vol.Optional(CONF_REQUEST_TIMEOUT, default=DEFAULT_REQUEST_TIMEOUT): int,
                vol.Optional(CONF_UPDATE_INTERVAL, default=DEFAULT_UPDATE_INTERVAL): int,
            }
        )
        return self.async_show_form(step_id="user", data_schema=schema, errors=errors)
