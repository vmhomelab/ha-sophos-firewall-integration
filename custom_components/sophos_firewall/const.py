DOMAIN = "sophos_firewall"
PLATFORMS = ["sensor"]

CONF_VERIFY_SSL = "verify_ssl"
CONF_REQUEST_TIMEOUT = "request_timeout"
CONF_UPDATE_INTERVAL = "update_interval"

DEFAULT_VERIFY_SSL = False
DEFAULT_REQUEST_TIMEOUT = 8
DEFAULT_UPDATE_INTERVAL = 300
MAX_REQUEST_TIMEOUT = 8

REPORT_BLOCKED_TRAFFIC = "blocked_traffic"
REPORT_ALLOWED_TRAFFIC = "allowed_traffic"
REPORT_ALLOWED_APPLICATION_CATEGORIES = "allowed_application_categories"
REPORT_ALLOWED_WEB_CATEGORIES = "allowed_web_categories"
REPORT_SOURCE_COUNTRIES = "source_countries"
REPORT_DESTINATION_COUNTRIES = "destination_countries"
REPORT_WEB_DOMAINS = "web_domains"
REPORT_TOP_HOSTS = "top_hosts"
