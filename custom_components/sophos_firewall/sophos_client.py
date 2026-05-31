from __future__ import annotations

from dataclasses import dataclass
import logging
from typing import Final
from xml.sax.saxutils import escape

import httpx

from .parser import ReportData, parse_report_response

API_PATH: Final = "/webconsole/APIController"
_LOGGER = logging.getLogger(__name__)

REPORT_PAYLOADS: Final[dict[str, str]] = {
    "blocked_traffic": """<Get><Report><Name>BlockedTraffic</Name></Report></Get>""",
    "allowed_traffic": """<Get><Report><Name>AllowedTraffic</Name></Report></Get>""",
    "allowed_application_categories": """<Get><Report><Name>AllowedApplicationCategories</Name></Report></Get>""",
    "allowed_web_categories": """<Get><Report><Name>AllowedWebCategories</Name></Report></Get>""",
    "source_countries": """<Get><Report><Name>SourceCountries</Name></Report></Get>""",
    "destination_countries": """<Get><Report><Name>DestinationCountries</Name></Report></Get>""",
    "web_domains": """<Get><Report><Name>WebDomains</Name></Report></Get>""",
    "top_hosts": """<Get><Report><Name>TopHosts</Name></Report></Get>""",
}


@dataclass(slots=True)
class SophosFirewallClient:
    host: str
    username: str
    password: str
    verify_ssl: bool = False
    timeout: int = 8

    @property
    def api_url(self) -> str:
        return f"{self.host.rstrip('/')}{API_PATH}"

    @property
    def http_timeout(self) -> httpx.Timeout:
        # Keep total time below Home Assistant's 10 second slow-update warning.
        return httpx.Timeout(timeout=float(self.timeout), connect=min(5.0, float(self.timeout)))

    def _wrap(self, payload: str) -> str:
        return f"""<Request>
  <Login>
    <Username>{escape(self.username)}</Username>
    <Password>{escape(self.password)}</Password>
  </Login>
  {payload}
</Request>"""

    async def post_xml(self, payload: str) -> str:
        _LOGGER.debug("Posting Sophos XML API request to %s", self.api_url)
        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=self.http_timeout) as client:
            response = await client.post(self.api_url, data={"reqxml": self._wrap(payload)})
        _LOGGER.debug("Sophos XML API response status: %s", response.status_code)
        response.raise_for_status()
        if not response.text.strip():
            raise RuntimeError("Sophos API returned an empty response")
        return response.text

    async def fetch_report(self, report_key: str) -> ReportData:
        payload = REPORT_PAYLOADS[report_key]
        return parse_report_response(await self.post_xml(payload))
