from __future__ import annotations

from dataclasses import dataclass
import logging
from typing import Final
from urllib.parse import urlsplit, urlunsplit
from xml.sax.saxutils import escape
import xml.etree.ElementTree as ET

import httpx

from .parser import ReportData, parse_report_response

API_PATH: Final = "/webconsole/APIController"
DEFAULT_API_PORT: Final = 4444
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


def _normalize_host(host: str) -> str:
    """Return a Sophos XML API base URL.

    SFOS exposes the XML API on the web admin listener, normally HTTPS/4444.
    Users often enter only the firewall IP or the plain web URL; normalize those
    forms so the integration does not silently poll port 80/443 and time out.
    """
    value = host.strip().rstrip("/")
    if "://" not in value:
        value = f"https://{value}"

    parsed = urlsplit(value)
    scheme = "https" if parsed.scheme in {"http", "https"} else parsed.scheme
    netloc = parsed.netloc
    if parsed.hostname and parsed.port is None:
        host_part = parsed.hostname
        if ":" in host_part and not host_part.startswith("["):
            host_part = f"[{host_part}]"
        if parsed.username:
            auth = parsed.username
            if parsed.password:
                auth = f"{auth}:{parsed.password}"
            host_part = f"{auth}@{host_part}"
        netloc = f"{host_part}:{DEFAULT_API_PORT}"

    return urlunsplit((scheme, netloc, parsed.path, "", ""))


def _strip_namespace(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _response_status(xml_text: str) -> str | None:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None

    for node in root.iter():
        if _strip_namespace(node.tag).lower() == "status" and node.text:
            value = node.text.strip()
            if value:
                return value
    return None


@dataclass(slots=True)
class SophosFirewallClient:
    host: str
    username: str
    password: str
    verify_ssl: bool = False
    timeout: int = 8

    @property
    def base_url(self) -> str:
        return _normalize_host(self.host)

    @property
    def api_url(self) -> str:
        return f"{self.base_url.rstrip('/')}{API_PATH}"

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

        status = _response_status(response.text)
        if status and status.lower() not in {"success", "successful"}:
            raise RuntimeError(f"Sophos API status: {status}")

        return response.text

    async def fetch_report(self, report_key: str) -> ReportData:
        payload = REPORT_PAYLOADS[report_key]
        return parse_report_response(await self.post_xml(payload))
