# Sophos Firewall Home Assistant Integration

Custom Home Assistant integration for Sophos Firewall / SFOS monitoring sensors.

## Current development state

This repository is intentionally created with a `dev` branch for active work. The initial implementation provides the Home Assistant integration scaffold, XML API client, parser, coordinator, and sensor entities.

The exact SFOS report payloads may need adjustment against a real firewall XML API response. The client already uses the correct SFOS API request shape: XML inside the `reqxml` form field.

Report fetches are bounded to stay below Home Assistant's slow-update warning threshold. Failed report requests are logged per report and exposed as `last_error` on the affected sensor instead of blocking the entire coordinator update.

## Planned sensors

- Blocked traffic
- Allowed traffic
- Top allowed application category
- Top allowed web category
- Top source country
- Top destination country
- Top web domain
- Top host

Each top-list sensor exposes the top item as the state and the top 10 rows as attributes:

```yaml
total_hits: 123
total_bytes: 456789
top:
  - name: Germany
    hits: 42
    bytes: 12345
```

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
