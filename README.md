# Sophos Firewall Home Assistant Integration

Custom Home Assistant integration for Sophos Firewall / SFOS monitoring sensors.

## Current development state

This repository is intentionally created with a `dev` branch for active work. The implementation provides the Home Assistant integration scaffold, XML API client, parser, coordinator, and sensor entities.

The integration uses Sophos' official XML API request format: XML inside the `reqxml` form field posted to `/webconsole/APIController` on the firewall web admin listener, usually HTTPS port `4444`.

## Important API scope note

Sophos' official Postman collection documents configuration XML API objects such as firewall rules, NAT rules, interfaces, hosts, services, ACLs, and schedules. It does **not** document the earlier guessed live dashboard/report objects such as `BlockedTraffic` or `TopHosts`.

For that reason, this integration now exposes stable configuration inventory sensors first instead of polling unsupported report payloads that can time out on real SFOS devices.

## Sensors

The current sensors expose object counts as their state and the first 10 returned objects as attributes:

- Sophos Firewall Rules
- Sophos Firewall Rule Groups
- Sophos NAT Rules
- Sophos SSL TLS Inspection Rules
- Sophos Web Filter Exceptions
- Sophos Interfaces
- Sophos IP Hosts
- Sophos FQDN Hosts
- Sophos MAC Hosts
- Sophos Services
- Sophos Local Service ACL Rules
- Sophos Schedules

Example attributes:

```yaml
count: 2
items:
  - name: LAN to WAN
    attributes:
      Name: LAN to WAN
      Status: Enable
      IPFamily: IPv4
```

Failed resource requests are logged per resource and exposed as `last_error` on the affected sensor instead of blocking the entire coordinator update.

## Installation

### HACS custom repository

1. HACS → Integrations → three-dot menu → Custom repositories.
2. Add this repository URL.
3. Category: Integration.
4. Install **Sophos Firewall**.
5. Restart Home Assistant.
6. Settings → Devices & services → Add integration → Sophos Firewall.

### Manual installation

Copy the folder below into Home Assistant:

```text
custom_components/sophos_firewall
```

Restart Home Assistant and add the integration from the UI.

## Configuration

Required:

- Sophos host URL, for example `https://192.0.2.10:4444`
- API username
- API password

Optional:

- Verify SSL certificate
- Request timeout
- Update interval

## Sophos prerequisites

On the Sophos firewall:

1. Enable XML API access.
2. Use a dedicated low-privilege API user where possible.
3. Allow the Home Assistant host IP as an API requester.
4. Keep XML API exposure limited to the management network.

## Security

Do not commit credentials. Credentials are stored in Home Assistant config entries.

## Development

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
pytest -q
```
