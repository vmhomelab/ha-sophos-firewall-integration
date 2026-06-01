from __future__ import annotations

from dataclasses import dataclass
import logging
from typing import Final
from urllib.parse import urlsplit, urlunsplit
from xml.sax.saxutils import escape
import xml.etree.ElementTree as ET

import httpx

from .parser import ResourceData, parse_resource_response

API_PATH: Final = "/webconsole/APIController"
DEFAULT_API_PORT: Final = 4444
_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class SophosResourceDefinition:
    key: str
    tag: str
    payload: str


# These objects come from Sophos' official Postman collection:
# https://docs.sophos.com/nsg/sophos-firewall/api-collections/sophosfirewall.postman_collection.json
# They are configuration resources, not live report/dashboard queries.
RESOURCE_DEFINITIONS: Final[tuple[SophosResourceDefinition, ...]] = (
    SophosResourceDefinition("firewall_rules", "FirewallRule", "<Get><FirewallRule></FirewallRule></Get>"),
    SophosResourceDefinition("firewall_rule_groups", "FirewallRuleGroup", "<Get><FirewallRuleGroup></FirewallRuleGroup></Get>"),
    SophosResourceDefinition("nat_rules", "NATRule", "<Get><NATRule></NATRule></Get>"),
    SophosResourceDefinition("ssl_tls_inspection_rules", "SSLTLSInspectionRule", "<Get><SSLTLSInspectionRule></SSLTLSInspectionRule></Get>"),
    SophosResourceDefinition("web_filter_exceptions", "WebFilterException", "<Get><WebFilterException></WebFilterException></Get>"),
    SophosResourceDefinition("interfaces", "Interface", "<Get><Interface></Interface></Get>"),
    SophosResourceDefinition("ip_hosts", "IPHost", "<Get><IPHost></IPHost></Get>"),
    SophosResourceDefinition("fqdn_hosts", "FQDNHost", "<Get><FQDNHost></FQDNHost></Get>"),
    SophosResourceDefinition("mac_hosts", "MACHost", "<Get><MACHost></MACHost></Get>"),
    SophosResourceDefinition("services", "Services", "<Get><Services></Services></Get>"),
    SophosResourceDefinition("local_service_acl_rules", "LocalServiceACL", "<Get><LocalServiceACL></LocalServiceACL></Get>"),
    SophosResourceDefinition("schedules", "Schedule", "<Get><Schedule></Schedule></Get>"),
)
RESOURCE_DEFINITIONS_BY_KEY: Final = {definition.key: definition for definition in RESOURCE_DEFINITIONS}


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
        # Keep per-resource request time below Home Assistant's 10 second slow-update warning.
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
        if status:
            normalized_status = status.lower()
            if any(term in normalized_status for term in ("failure", "failed", "denied", "error")):
                raise RuntimeError(f"Sophos API status: {status}")

        return response.text

    async def fetch_resource(self, resource_key: str) -> ResourceData:
        definition = RESOURCE_DEFINITIONS_BY_KEY[resource_key]
        return parse_resource_response(await self.post_xml(definition.payload), definition.tag)
