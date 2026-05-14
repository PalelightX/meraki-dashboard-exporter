"""Client metrics collector for network-wide client data."""

from __future__ import annotations

import asyncio
import math
import time
from typing import Any

import structlog

from ..core.api_helpers import create_api_helper
from ..core.api_models import NetworkClient
from ..core.batch_processing import process_in_batches_with_errors
from ..core.collector import MetricCollector
from ..core.constants import ClientMetricName, UpdateTier
from ..core.error_handling import (
    ErrorCategory,
    validate_response_format,
    with_error_handling,
)
from ..core.label_helpers import create_client_labels, create_network_labels
from ..core.logging_decorators import log_api_call, log_collection_progress
from ..core.metrics import LabelName
from ..core.registry import register_collector
from ..services.client_store import ClientStore
from ..services.dns_resolver import DNSResolver

logger = structlog.get_logger(__name__)


@register_collector(UpdateTier.MEDIUM)
class ClientsCollector(MetricCollector):
    """Collector for client-level metrics across all networks."""

    @property
    def is_active(self) -> bool:
        """Check if this collector is actively collecting metrics."""
        return getattr(self, "_enabled", False)

    def __init__(self, *args: Any, **kwargs: Any):
        """Initialize the clients collector.

        Parameters
        ----------
        *args : Any
            Positional arguments passed to parent.
        **kwargs : Any
            Keyword arguments passed to parent.

        """
        super().__init__(*args, **kwargs)

        # Check if client collection is enabled
        if not self.settings.clients.enabled:
            logger.info("Client data collection is disabled")
            self._enabled = False
            return

        self._enabled = True
        self.api_helper = create_api_helper(self)

        # Initialize services
        self.client_store = ClientStore(self.settings)
        self.dns_resolver = DNSResolver(self.settings)

        # Initialize DNS stats tracking
        self._last_dns_stats: dict[str, int] | None = None
        self._last_app_usage_by_network: dict[str, float] = {}
        self._signal_quality_rotation_by_network: dict[str, int] = {}
        self._signal_quality_network_rotation_index = 0
        self._signal_quality_allowed_network_ids: set[str] | None = None
        self._signal_quality_lock = asyncio.Lock()
        self._signal_quality_previous_total_wireless_clients = 0
        self._signal_quality_current_total_wireless_clients = 0
        self._signal_quality_cycle_budget = 0
        self._signal_quality_remaining_budget = 0
        self._signal_quality_cycle_collected_count = 0
        self._signal_quality_cycle_metric_count = 0
        self._signal_quality_cycle_missing_data_count = 0
        self._signal_quality_cycle_error_count = 0

    def _initialize_metrics(self) -> None:
        """Initialize Prometheus metrics for client data."""
        # Skip metric initialization if collector is disabled
        if not self.settings.clients.enabled:
            return

        # Client status metric (1 = online, 0 = offline)
        self.client_status = self._create_gauge(
            ClientMetricName.CLIENT_STATUS,
            "Client online status (1 = online, 0 = offline)",
            labelnames=[
                LabelName.ORG_ID,
                LabelName.ORG_NAME,
                LabelName.NETWORK_ID,
                LabelName.NETWORK_NAME,
                LabelName.CLIENT_ID,
                LabelName.MAC,
                LabelName.DESCRIPTION,
                LabelName.HOSTNAME,
                LabelName.SSID,
            ],
        )

        # Client usage metrics - using Gauge since these are point-in-time measurements
        # that can go up or down (hourly usage windows from API)
        self.client_usage_sent = self._create_gauge(
            ClientMetricName.CLIENT_USAGE_SENT_KB,
            "Kilobytes sent by client in the last hour",
            labelnames=[
                LabelName.ORG_ID,
                LabelName.ORG_NAME,
                LabelName.NETWORK_ID,
                LabelName.NETWORK_NAME,
                LabelName.CLIENT_ID,
                LabelName.MAC,
                LabelName.DESCRIPTION,
                LabelName.HOSTNAME,
                LabelName.SSID,
            ],
        )

        self.client_usage_recv = self._create_gauge(
            ClientMetricName.CLIENT_USAGE_RECV_KB,
            "Kilobytes received by client in the last hour",
            labelnames=[
                LabelName.ORG_ID,
                LabelName.ORG_NAME,
                LabelName.NETWORK_ID,
                LabelName.NETWORK_NAME,
                LabelName.CLIENT_ID,
                LabelName.MAC,
                LabelName.DESCRIPTION,
                LabelName.HOSTNAME,
                LabelName.SSID,
            ],
        )

        self.client_usage_total = self._create_gauge(
            ClientMetricName.CLIENT_USAGE_TOTAL_KB,
            "Total kilobytes transferred by client in the last hour",
            labelnames=[
                LabelName.ORG_ID,
                LabelName.ORG_NAME,
                LabelName.NETWORK_ID,
                LabelName.NETWORK_NAME,
                LabelName.CLIENT_ID,
                LabelName.MAC,
                LabelName.DESCRIPTION,
                LabelName.HOSTNAME,
                LabelName.SSID,
            ],
        )

        # DNS cache metrics
        self.dns_cache_total = self._create_gauge(
            "meraki_exporter_client_dns_cache_total",
            "Total number of entries in DNS cache",
        )

        self.dns_cache_valid = self._create_gauge(
            "meraki_exporter_client_dns_cache_valid",
            "Number of valid entries in DNS cache",
        )

        self.dns_cache_expired = self._create_gauge(
            "meraki_exporter_client_dns_cache_expired",
            "Number of expired entries in DNS cache",
        )

        self.dns_lookups_total = self._create_counter(
            "meraki_exporter_client_dns_lookups_total",
            "Total number of DNS lookups performed",
        )

        self.dns_lookups_successful = self._create_counter(
            "meraki_exporter_client_dns_lookups_successful_total",
            "Total number of successful DNS lookups",
        )

        self.dns_lookups_failed = self._create_counter(
            "meraki_exporter_client_dns_lookups_failed_total",
            "Total number of failed DNS lookups",
        )

        self.dns_lookups_cached = self._create_counter(
            "meraki_exporter_client_dns_lookups_cached_total",
            "Total number of DNS lookups served from cache",
        )

        # Client store metrics
        self.client_store_total = self._create_gauge(
            "meraki_exporter_client_store_total",
            "Total number of clients in the store",
        )

        self.client_store_networks = self._create_gauge(
            "meraki_exporter_client_store_networks",
            "Total number of networks with clients",
        )

        # Client capability metrics
        self.client_capabilities_count = self._create_gauge(
            ClientMetricName.WIRELESS_CLIENT_CAPABILITIES_COUNT,
            "Count of wireless clients by capability",
            labelnames=[
                LabelName.ORG_ID,
                LabelName.ORG_NAME,
                LabelName.NETWORK_ID,
                LabelName.NETWORK_NAME,
                LabelName.TYPE,  # For the capability type
            ],
        )

        # Client distribution metrics
        self.clients_per_ssid = self._create_gauge(
            ClientMetricName.CLIENTS_PER_SSID_COUNT,
            "Count of clients per SSID",
            labelnames=[
                LabelName.ORG_ID,
                LabelName.ORG_NAME,
                LabelName.NETWORK_ID,
                LabelName.NETWORK_NAME,
                LabelName.SSID,
            ],
        )

        self.clients_per_vlan = self._create_gauge(
            ClientMetricName.CLIENTS_PER_VLAN_COUNT,
            "Count of clients per VLAN",
            labelnames=[
                LabelName.ORG_ID,
                LabelName.ORG_NAME,
                LabelName.NETWORK_ID,
                LabelName.NETWORK_NAME,
                LabelName.VLAN,
            ],
        )

        # Client application usage metrics
        self.client_app_usage_sent = self._create_gauge(
            ClientMetricName.CLIENT_APPLICATION_USAGE_SENT_KB,
            "Kilobytes sent by client per application in the last hour",
            labelnames=[
                LabelName.ORG_ID,
                LabelName.ORG_NAME,
                LabelName.NETWORK_ID,
                LabelName.NETWORK_NAME,
                LabelName.CLIENT_ID,
                LabelName.MAC,
                LabelName.DESCRIPTION,
                LabelName.HOSTNAME,
                LabelName.TYPE,  # For the application type
            ],
        )

        self.client_app_usage_recv = self._create_gauge(
            ClientMetricName.CLIENT_APPLICATION_USAGE_RECV_KB,
            "Kilobytes received by client per application in the last hour",
            labelnames=[
                LabelName.ORG_ID,
                LabelName.ORG_NAME,
                LabelName.NETWORK_ID,
                LabelName.NETWORK_NAME,
                LabelName.CLIENT_ID,
                LabelName.MAC,
                LabelName.DESCRIPTION,
                LabelName.HOSTNAME,
                LabelName.TYPE,  # For the application type
            ],
        )

        self.client_app_usage_total = self._create_gauge(
            ClientMetricName.CLIENT_APPLICATION_USAGE_TOTAL_KB,
            "Total kilobytes transferred by client per application in the last hour",
            labelnames=[
                LabelName.ORG_ID,
                LabelName.ORG_NAME,
                LabelName.NETWORK_ID,
                LabelName.NETWORK_NAME,
                LabelName.CLIENT_ID,
                LabelName.MAC,
                LabelName.DESCRIPTION,
                LabelName.HOSTNAME,
                LabelName.TYPE,  # For the application type
            ],
        )

        # Wireless client signal quality metrics
        self.wireless_client_rssi = self._create_gauge(
            ClientMetricName.WIRELESS_CLIENT_RSSI,
            "Wireless client RSSI (Received Signal Strength Indicator) in dBm",
            labelnames=[
                LabelName.ORG_ID,
                LabelName.ORG_NAME,
                LabelName.NETWORK_ID,
                LabelName.NETWORK_NAME,
                LabelName.CLIENT_ID,
                LabelName.MAC,
                LabelName.DESCRIPTION,
                LabelName.HOSTNAME,
                LabelName.SSID,
                LabelName.AP_SERIAL,
                LabelName.AP_NAME,
                LabelName.AP_MAC,
            ],
        )

        self.wireless_client_snr = self._create_gauge(
            ClientMetricName.WIRELESS_CLIENT_SNR,
            "Wireless client SNR (Signal-to-Noise Ratio) in dB",
            labelnames=[
                LabelName.ORG_ID,
                LabelName.ORG_NAME,
                LabelName.NETWORK_ID,
                LabelName.NETWORK_NAME,
                LabelName.CLIENT_ID,
                LabelName.MAC,
                LabelName.DESCRIPTION,
                LabelName.HOSTNAME,
                LabelName.SSID,
                LabelName.AP_SERIAL,
                LabelName.AP_NAME,
                LabelName.AP_MAC,
            ],
        )

    async def _collect_impl(self) -> None:
        """Collect client metrics from all organizations and networks."""
        if not self._enabled:
            logger.debug("Client collection is disabled, skipping")
            return

        organizations = await self.api_helper.get_organizations()

        if not organizations:
            return

        await self._start_signal_quality_cycle()

        for org in organizations:
            org_id = org["id"]
            org_name = org["name"]

            # Get all networks for the organization
            networks = await self.api_helper.get_organization_networks(org_id)

            if not networks:
                continue

            # Process networks directly without batching to avoid lambda issues
            # Since we're already processing one org at a time, this is fine
            await self._process_network_batch(org_id, org_name, networks)

        await self._finish_signal_quality_cycle()

        # Update DNS cache and client store metrics after all collections
        self._update_cache_metrics()

    async def _process_network_batch(
        self,
        org_id: str,
        org_name: str,
        networks: list[Any],
    ) -> None:
        """Process a batch of networks for client collection.

        Parameters
        ----------
        org_id : str
            Organization ID.
        org_name : str
            Organization name.
        networks : list[Any]
            List of networks to process.

        """
        if not networks:
            return

        networks = self._prepare_signal_quality_network_rotation(networks)
        batch_size = self.settings.api.client_batch_size
        delay_between_batches = self.settings.api.batch_delay

        async def _process_network(network: dict[str, Any]) -> None:
            await self._collect_network_clients(
                org_id,
                org_name,
                network["id"],
                network["name"],
            )

        await process_in_batches_with_errors(
            networks,
            _process_network,
            batch_size=batch_size,
            delay_between_batches=delay_between_batches,
            spread_over_seconds=self._get_smoothing_window(),
            initial_delay=self._get_smoothing_offset(f"{org_id}:clients"),
            min_batch_delay=self.settings.api.smoothing_min_batch_delay,
            max_batch_delay=self.settings.api.smoothing_max_batch_delay,
            item_description="network",
            error_context_func=lambda network: {
                "org_id": org_id,
                "org_name": org_name,
                "network_id": network.get("id"),
                "network_name": network.get("name"),
            },
        )

    @with_error_handling(
        operation="Collect network clients",
        continue_on_error=True,
        error_category=ErrorCategory.API_CLIENT_ERROR,
    )
    @log_api_call("getNetworkClients")
    async def _collect_network_clients(
        self,
        org_id: str,
        org_name: str,
        network_id: str,
        network_name: str,
    ) -> None:
        """Collect client data for a specific network.

        Parameters
        ----------
        org_id : str
            Organization ID.
        org_name : str
            Organization name.
        network_id : str
            Network ID.
        network_name : str
            Network name.

        """
        logger.debug(
            "Collecting client data",
            org_id=org_id,
            org_name=org_name,
            network_id=network_id,
            network_name=network_name,
        )

        # Always fetch fresh data from API to get current status and usage
        # The cache is only used for hostname lookups, not for skipping API calls
        self._track_api_call("getNetworkClients")
        try:
            clients_data = await asyncio.to_thread(
                self.api.networks.getNetworkClients,
                network_id,
                timespan=3600,  # 1 hour as requested
                perPage=5000,  # Maximum allowed
                total_pages="all",
            )
        except Exception as e:
            logger.error(
                "Failed to fetch clients",
                org_id=org_id,
                network_id=network_id,
                network_name=network_name,
                error=str(e),
            )
            self._track_error(ErrorCategory.API_CLIENT_ERROR)
            return

        # Validate response format (handles API error responses like rate limits)
        clients_data = validate_response_format(
            clients_data, expected_type=list, operation="getNetworkClients"
        )

        # Parse client data
        clients = [NetworkClient.model_validate(c) for c in clients_data]

        logger.info(
            "Fetched client data",
            org_id=org_id,
            network_id=network_id,
            network_name=network_name,
            client_count=len(clients),
        )

        # Prepare client data for DNS resolution
        client_data = [(c.id, c.ip, c.description) for c in clients]

        # Resolve hostnames with client tracking
        logger.debug(
            "Resolving hostnames for network",
            network_id=network_id,
            client_count=len(clients),
        )
        hostnames = await self.dns_resolver.resolve_multiple(client_data)

        # Update client store
        self.client_store.update_clients(
            network_id,
            clients,
            network_name=network_name,
            org_id=org_id,
            hostnames=hostnames,
        )

        # Update metrics
        await self._update_metrics(org_id, org_name, network_id, network_name, clients, hostnames)

        # Collect application usage data
        await self._collect_application_usage(
            org_id, org_name, network_id, network_name, clients, hostnames
        )

        # Collect wireless signal quality data within the per-cycle budget.
        await self._collect_wireless_signal_quality(
            org_id, org_name, network_id, network_name, clients, hostnames
        )

    def _sanitize_label_value(self, value: str | None, max_length: int = 2048) -> str:
        """Sanitize a label value for Prometheus.

        Parameters
        ----------
        value : str | None
            Value to sanitize.
        max_length : int
            Maximum length for the label value.

        Returns
        -------
        str
            Sanitized value.

        """
        if not value:
            return ""

        # Replace characters not allowed in Prometheus labels with hyphen
        # Allowed: [a-zA-Z0-9_-]
        sanitized = ""
        for char in value:
            if char.isalnum() or char in "_- ":
                sanitized += char
            else:
                sanitized += "-"

        # Truncate to max length
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length]

        return sanitized

    def _sanitize_capability_for_metric(self, capability: str | None) -> str:
        """Sanitize wireless capability string for use as a metric label.

        Converts capability strings like "802.11ac - 2.4 and 5 GHz" to
        a more metric-friendly format like "802_11ac_2_4_and_5_ghz".

        Parameters
        ----------
        capability : str | None
            Wireless capability string.

        Returns
        -------
        str
            Sanitized capability string suitable for metric labels.

        """
        if not capability:
            return "unknown"

        # Convert to lowercase and replace common patterns
        sanitized = capability.lower()

        # Replace dots with underscores (802.11 -> 802_11)
        sanitized = sanitized.replace(".", "_")

        # Replace spaces and hyphens with underscores
        sanitized = sanitized.replace(" - ", "_")
        sanitized = sanitized.replace(" ", "_")
        sanitized = sanitized.replace("-", "_")

        # Remove any remaining non-alphanumeric characters except underscores
        result = ""
        for char in sanitized:
            if char.isalnum() or char == "_":
                result += char

        # Clean up multiple consecutive underscores
        while "__" in result:
            result = result.replace("__", "_")

        # Remove leading/trailing underscores
        result = result.strip("_")

        return result if result else "unknown"

    def _create_recent_ap_labels(self, client: NetworkClient) -> dict[str, str]:
        """Create labels for the client's most recent AP association."""
        return {
            LabelName.AP_SERIAL.value: client.recentDeviceSerial or "",
            LabelName.AP_NAME.value: self._sanitize_label_value(client.recentDeviceName),
            LabelName.AP_MAC.value: client.recentDeviceMac or "",
        }

    def _sanitize_application_name(self, app_name: str | None) -> str:
        """Sanitize application name for use as a metric label.

        Converts application names like "Google HTTPS" to a more
        metric-friendly format like "google_https".

        Parameters
        ----------
        app_name : str | None
            Application name from Meraki API.

        Returns
        -------
        str
            Sanitized application name suitable for metric labels.

        """
        if not app_name:
            return "unknown"

        # Convert to lowercase
        sanitized = app_name.lower()

        # Replace common patterns
        sanitized = sanitized.replace(" - ", "_")
        sanitized = sanitized.replace(" ", "_")
        sanitized = sanitized.replace("-", "_")
        sanitized = sanitized.replace("(", "_")
        sanitized = sanitized.replace(")", "_")
        sanitized = sanitized.replace("/", "_")
        sanitized = sanitized.replace("\\", "_")
        sanitized = sanitized.replace(".", "_")
        sanitized = sanitized.replace(",", "_")
        sanitized = sanitized.replace(":", "_")
        sanitized = sanitized.replace(";", "_")
        sanitized = sanitized.replace("'", "")
        sanitized = sanitized.replace('"', "")

        # Remove any remaining non-alphanumeric characters except underscores
        result = ""
        for char in sanitized:
            if char.isalnum() or char == "_":
                result += char

        # Clean up multiple consecutive underscores
        while "__" in result:
            result = result.replace("__", "_")

        # Remove leading/trailing underscores
        result = result.strip("_")

        return result if result else "unknown"

    def _determine_hostname(
        self,
        client: NetworkClient,
        resolved_hostname: str | None,
    ) -> str:
        """Determine the hostname to use for a client.

        Priority:
        1. Resolved hostname from DNS
        2. Client description (if not empty)
        3. Client IP address
        4. "unknown"

        Parameters
        ----------
        client : NetworkClient
            Client data.
        resolved_hostname : str | None
            Hostname resolved from DNS.

        Returns
        -------
        str
            Hostname to use.

        """
        # Priority 1: DNS resolved hostname
        if resolved_hostname:
            return resolved_hostname

        # Priority 2: Client description
        if client.description:
            return client.description

        # Priority 3: Client IP
        if client.ip:
            return client.ip

        # Priority 4: Fallback
        return "unknown"

    @log_collection_progress("clients")
    async def _update_metrics(
        self,
        org_id: str,
        org_name: str,
        network_id: str,
        network_name: str,
        clients: list[NetworkClient],
        hostnames: dict[str, str | None],
        current: int = 0,
        total: int = 0,
    ) -> None:
        """Update Prometheus metrics for clients.

        Parameters
        ----------
        org_id : str
            Organization ID.
        org_name : str
            Organization name.
        network_id : str
            Network ID.
        network_name : str
            Network name.
        clients : list[NetworkClient]
            List of clients.
        hostnames : dict[str, str | None]
            Resolved hostnames by IP.
        current : int
            Current progress (for logging).
        total : int
            Total items (for logging).

        """
        # Track counts for aggregated metrics
        capabilities_count: dict[str, int] = {}
        ssid_count: dict[str, int] = {}
        vlan_count: dict[str, int] = {}

        for client in clients:
            # Get resolved hostname from DNS
            resolved_hostname = hostnames.get(client.ip) if client.ip else None

            # Determine final hostname using fallback logic
            hostname = self._determine_hostname(client, resolved_hostname)

            # Sanitize label values
            sanitized_hostname = self._sanitize_label_value(hostname)
            sanitized_description = self._sanitize_label_value(client.description)

            # Determine effective SSID
            ssid = client.ssid if client.recentDeviceConnection == "Wireless" else "Wired"

            # Track aggregated counts
            # 1. Wireless capabilities (only for wireless clients)
            if client.recentDeviceConnection == "Wireless" and client.wirelessCapabilities:
                cap_key = self._sanitize_capability_for_metric(client.wirelessCapabilities)
                capabilities_count[cap_key] = capabilities_count.get(cap_key, 0) + 1

            # 2. SSID counts
            ssid_key = ssid or "Unknown"
            ssid_count[ssid_key] = ssid_count.get(ssid_key, 0) + 1

            # 3. VLAN counts
            vlan_key = str(client.vlan) if client.vlan else "untagged"
            vlan_count[vlan_key] = vlan_count.get(vlan_key, 0) + 1

            # Create client labels using helper
            client_data = {
                "id": client.id,
                "mac": client.mac,
                "description": sanitized_description,
                "hostname": sanitized_hostname,
            }
            labels = create_client_labels(
                client_data,
                org_id=org_id,
                org_name=org_name,
                network_id=network_id,
                network_name=network_name,
                ssid=ssid or "Unknown",
            )

            # Set client status
            status_value = 1 if client.status == "Online" else 0
            self.client_status.labels(**labels).set(status_value)

            # Set usage metrics (as gauges - these are point-in-time measurements)
            if client.usage:
                sent_kb = client.usage.get("sent", 0)
                recv_kb = client.usage.get("recv", 0)
                total_kb = client.usage.get("total", 0)

                # Set gauge values
                self.client_usage_sent.labels(**labels).set(float(sent_kb))
                self.client_usage_recv.labels(**labels).set(float(recv_kb))
                self.client_usage_total.labels(**labels).set(float(total_kb))

            logger.debug(
                "Updated client metrics",
                client_id=client.id,
                mac=client.mac,
                description=client.description,
                hostname=hostname,
                status=client.status,
                ssid=ssid,
            )

        # Update aggregated metrics after processing all clients
        # 1. Wireless capabilities metrics
        for capability, count in capabilities_count.items():
            # Use create_network_labels for network-level metrics
            network_data = {"id": network_id, "name": network_name}
            cap_labels = create_network_labels(
                network_data,
                org_id=org_id,
                org_name=org_name,
                type=capability,
            )
            self.client_capabilities_count.labels(**cap_labels).set(count)
            logger.debug(
                "Set wireless capability count",
                capability=capability,
                count=count,
                network_id=network_id,
            )

        # 2. SSID metrics
        for ssid_name, count in ssid_count.items():
            # Use create_network_labels for network-level metrics
            network_data = {"id": network_id, "name": network_name}
            ssid_labels = create_network_labels(
                network_data,
                org_id=org_id,
                org_name=org_name,
                ssid=ssid_name,
            )
            self.clients_per_ssid.labels(**ssid_labels).set(count)
            logger.debug(
                "Set SSID client count",
                ssid=ssid_name,
                count=count,
                network_id=network_id,
            )

        # 3. VLAN metrics
        for vlan_id, count in vlan_count.items():
            # Use create_network_labels for network-level metrics
            network_data = {"id": network_id, "name": network_name}
            vlan_labels = create_network_labels(
                network_data,
                org_id=org_id,
                org_name=org_name,
                vlan=vlan_id,
            )
            self.clients_per_vlan.labels(**vlan_labels).set(count)
            logger.debug(
                "Set VLAN client count",
                vlan=vlan_id,
                count=count,
                network_id=network_id,
            )

    @with_error_handling(
        operation="Collect application usage",
        continue_on_error=True,
        error_category=ErrorCategory.API_CLIENT_ERROR,
    )
    @log_api_call("getNetworkClientsApplicationUsage")
    async def _collect_application_usage(
        self,
        org_id: str,
        org_name: str,
        network_id: str,
        network_name: str,
        clients: list[NetworkClient],
        hostnames: dict[str, str | None],
    ) -> None:
        """Collect application usage data for clients.

        Parameters
        ----------
        org_id : str
            Organization ID.
        org_name : str
            Organization name.
        network_id : str
            Network ID.
        network_name : str
            Network name.
        clients : list[NetworkClient]
            List of clients.
        hostnames : dict[str, str | None]
            Resolved hostnames by IP.

        """
        if not clients:
            return

        interval = self.settings.api.client_app_usage_interval
        last_run = self._last_app_usage_by_network.get(network_id, 0.0)
        if interval > 0 and (time.time() - last_run) < interval:
            logger.debug(
                "Skipping client application usage collection",
                network_id=network_id,
                interval_seconds=interval,
            )
            return

        # Extract client IDs
        client_ids = [client.id for client in clients]

        # Create a lookup map for client data
        client_map = {client.id: client for client in clients}

        logger.debug(
            "Fetching application usage data",
            network_id=network_id,
            client_count=len(client_ids),
        )

        # Batch client IDs for API calls (using 1000 per batch as per API limit)
        batch_size = 1000
        for i in range(0, len(client_ids), batch_size):
            batch_ids = client_ids[i : i + batch_size]

            try:
                if i > 0:
                    self._track_api_call("getNetworkClientsApplicationUsage")
                rate_limiter = getattr(self, "rate_limiter", None)
                if rate_limiter is not None and i > 0:
                    await rate_limiter.acquire(org_id, "getNetworkClientsApplicationUsage")
                usage_data = await asyncio.to_thread(
                    self.api.networks.getNetworkClientsApplicationUsage,
                    network_id,
                    clients=",".join(batch_ids),
                    timespan=3600,  # 1 hour as requested
                    perPage=1000,
                    total_pages="all",
                )

                # Process usage data for each client
                for client_usage in usage_data:
                    client_id = client_usage.get("clientId")
                    if not client_id or client_id not in client_map:
                        continue

                    client = client_map[client_id]

                    # Get resolved hostname
                    resolved_hostname = hostnames.get(client.ip) if client.ip else None
                    hostname = self._determine_hostname(client, resolved_hostname)

                    # Sanitize label values
                    sanitized_hostname = self._sanitize_label_value(hostname)
                    sanitized_description = self._sanitize_label_value(client.description)

                    # Process each application's usage
                    for app_usage in client_usage.get("applicationUsage", []):
                        app_name = app_usage.get("application", "unknown")
                        sanitized_app = self._sanitize_application_name(app_name)

                        received_kb = app_usage.get("received", 0)
                        sent_kb = app_usage.get("sent", 0)
                        total_kb = received_kb + sent_kb

                        # Create client labels using helper
                        client_data = {
                            "id": client_id,
                            "mac": client.mac,
                            "description": sanitized_description,
                            "hostname": sanitized_hostname,
                        }
                        labels = create_client_labels(
                            client_data,
                            org_id=org_id,
                            org_name=org_name,
                            network_id=network_id,
                            network_name=network_name,
                            type=sanitized_app,
                        )

                        # Set metrics
                        self.client_app_usage_sent.labels(**labels).set(float(sent_kb))
                        self.client_app_usage_recv.labels(**labels).set(float(received_kb))
                        self.client_app_usage_total.labels(**labels).set(float(total_kb))

                        logger.debug(
                            "Set application usage metrics",
                            client_id=client_id,
                            application=app_name,
                            sanitized_app=sanitized_app,
                            sent_kb=sent_kb,
                            received_kb=received_kb,
                        )

            except Exception as e:
                logger.error(
                    "Failed to fetch application usage data",
                    network_id=network_id,
                    batch_start=i,
                    batch_size=len(batch_ids),
                    error=str(e),
                )
                self._track_error(ErrorCategory.API_CLIENT_ERROR)
                # Continue with next batch
                continue

        self._last_app_usage_by_network[network_id] = time.time()

        logger.info(
            "Completed application usage collection",
            network_id=network_id,
            client_count=len(client_ids),
        )

    def _compute_signal_quality_cycle_budget(self, total_wireless_clients: int) -> int:
        """Compute RSSI/SNR sample budget for the current collector cycle."""
        if total_wireless_clients <= 0:
            return 0

        tier_interval = max(1, self._get_tier_interval())
        target_interval = self.settings.clients.signal_quality_target_full_scan_interval
        cycles_per_scan = max(1, math.ceil(target_interval / tier_interval))
        target_per_cycle = math.ceil(total_wireless_clients / cycles_per_scan)
        min_per_cycle = self.settings.clients.signal_quality_min_clients_per_cycle
        max_per_cycle = self.settings.clients.signal_quality_max_clients_per_cycle
        budget = max(target_per_cycle, min_per_cycle)
        budget = min(budget, max_per_cycle, total_wireless_clients)
        return max(0, budget)

    def _prepare_signal_quality_network_rotation(self, networks: list[Any]) -> list[Any]:
        """Rotate network order and select networks eligible for RSSI/SNR this cycle."""
        if not self.settings.clients.signal_quality_enabled or not networks:
            self._signal_quality_allowed_network_ids = None
            return networks

        ordered_networks = sorted(networks, key=lambda network: network.get("id", ""))
        network_count = len(ordered_networks)
        start_index = self._signal_quality_network_rotation_index % network_count
        rotated_networks = ordered_networks[start_index:] + ordered_networks[:start_index]

        per_network_limit = self.settings.clients.signal_quality_max_clients_per_network
        network_slots = max(1, math.ceil(self._signal_quality_cycle_budget / per_network_limit))
        network_slots = min(network_slots, network_count)
        allowed_networks = rotated_networks[:network_slots]
        self._signal_quality_allowed_network_ids = {
            network["id"] for network in allowed_networks if network.get("id")
        }
        self._signal_quality_network_rotation_index = (start_index + network_slots) % network_count

        logger.info(
            "Prepared wireless signal quality network rotation",
            network_count=network_count,
            network_rotation_start_index=start_index,
            network_rotation_next_index=self._signal_quality_network_rotation_index,
            signal_quality_network_slots=network_slots,
            signal_quality_cycle_budget=self._signal_quality_cycle_budget,
        )
        return rotated_networks

    def _select_rotated_signal_quality_clients(
        self,
        network_id: str,
        clients: list[NetworkClient],
        limit: int,
    ) -> tuple[list[NetworkClient], int, int]:
        """Select clients using a per-network rotation cursor."""
        if not clients or limit <= 0:
            return [], 0, self._signal_quality_rotation_by_network.get(network_id, 0)

        client_count = len(clients)
        start_index = self._signal_quality_rotation_by_network.get(network_id, 0) % client_count
        sample_count = min(limit, client_count)
        selected = [
            clients[(start_index + offset) % client_count] for offset in range(sample_count)
        ]
        next_index = (start_index + sample_count) % client_count
        self._signal_quality_rotation_by_network[network_id] = next_index
        return selected, start_index, next_index

    async def _start_signal_quality_cycle(self) -> None:
        """Initialize per-cycle RSSI/SNR API budget."""
        if not self.settings.clients.signal_quality_enabled:
            return

        estimate = self._signal_quality_previous_total_wireless_clients
        if estimate <= 0:
            estimate = self.settings.clients.signal_quality_max_clients_per_cycle
        cycle_budget = self._compute_signal_quality_cycle_budget(estimate)
        async with self._signal_quality_lock:
            self._signal_quality_current_total_wireless_clients = 0
            self._signal_quality_cycle_budget = cycle_budget
            self._signal_quality_remaining_budget = cycle_budget
            self._signal_quality_cycle_collected_count = 0
            self._signal_quality_cycle_metric_count = 0
            self._signal_quality_cycle_missing_data_count = 0
            self._signal_quality_cycle_error_count = 0

        logger.info(
            "Starting wireless signal quality rotation",
            estimated_wireless_clients=estimate,
            signal_quality_cycle_budget=cycle_budget,
        )

    async def _finish_signal_quality_cycle(self) -> None:
        """Finalize per-cycle RSSI/SNR counters."""
        if not self.settings.clients.signal_quality_enabled:
            return

        async with self._signal_quality_lock:
            total_wireless_clients = self._signal_quality_current_total_wireless_clients
            self._signal_quality_previous_total_wireless_clients = total_wireless_clients
            cycle_budget = self._signal_quality_cycle_budget
            remaining_budget = self._signal_quality_remaining_budget
            collected_count = self._signal_quality_cycle_collected_count
            metric_count = self._signal_quality_cycle_metric_count
            missing_data_count = self._signal_quality_cycle_missing_data_count
            error_count = self._signal_quality_cycle_error_count

        logger.info(
            "Completed wireless signal quality rotation",
            total_wireless_clients=total_wireless_clients,
            signal_quality_cycle_budget=cycle_budget,
            signal_quality_remaining_budget=remaining_budget,
            signal_quality_collected_count=collected_count,
            signal_quality_metric_count=metric_count,
            signal_quality_missing_data_count=missing_data_count,
            signal_quality_error_count=error_count,
        )

    @with_error_handling(
        operation="Collect wireless signal quality",
        continue_on_error=True,
        error_category=ErrorCategory.API_CLIENT_ERROR,
    )
    @log_api_call("getNetworkWirelessSignalQualityHistory")
    async def _collect_wireless_signal_quality(
        self,
        org_id: str,
        org_name: str,
        network_id: str,
        network_name: str,
        clients: list[NetworkClient],
        hostnames: dict[str, str | None],
    ) -> None:
        """Collect wireless signal quality within the configured cycle budget."""
        if not self.settings.clients.signal_quality_enabled:
            return

        wireless_clients = [
            client for client in clients if client.recentDeviceConnection == "Wireless"
        ]
        wireless_clients.sort(key=lambda client: client.id or client.mac or "")

        if not wireless_clients:
            logger.debug("No wireless clients found in network", network_id=network_id)
            return

        async with self._signal_quality_lock:
            self._signal_quality_current_total_wireless_clients += len(wireless_clients)
            allowed_network_ids = self._signal_quality_allowed_network_ids
            if allowed_network_ids is not None and network_id not in allowed_network_ids:
                logger.info(
                    "Skipping wireless signal quality collection for network this cycle",
                    network_id=network_id,
                    network_name=network_name,
                    network_wireless_clients=len(wireless_clients),
                    signal_quality_remaining_budget=self._signal_quality_remaining_budget,
                )
                return
            network_limit = min(
                self.settings.clients.signal_quality_max_clients_per_network,
                self._signal_quality_remaining_budget,
            )
            selected_clients, rotation_start, rotation_next = (
                self._select_rotated_signal_quality_clients(
                    network_id,
                    wireless_clients,
                    network_limit,
                )
            )
            self._signal_quality_remaining_budget -= len(selected_clients)
            remaining_budget = self._signal_quality_remaining_budget

        if not selected_clients:
            logger.info(
                "Skipping wireless signal quality collection because cycle budget is exhausted",
                network_id=network_id,
                network_name=network_name,
                network_wireless_clients=len(wireless_clients),
                signal_quality_remaining_budget=remaining_budget,
            )
            return

        stats = await self._collect_wireless_signal_quality_for_clients(
            org_id=org_id,
            org_name=org_name,
            network_id=network_id,
            network_name=network_name,
            clients=selected_clients,
            hostnames=hostnames,
            network_wireless_clients=len(wireless_clients),
            rotation_start_index=rotation_start,
            rotation_next_index=rotation_next,
        )

        async with self._signal_quality_lock:
            self._signal_quality_cycle_collected_count += stats["collected_count"]
            self._signal_quality_cycle_metric_count += stats["metric_count"]
            self._signal_quality_cycle_missing_data_count += stats["missing_data_count"]
            self._signal_quality_cycle_error_count += stats["error_count"]

    async def _collect_wireless_signal_quality_for_clients(
        self,
        org_id: str,
        org_name: str,
        network_id: str,
        network_name: str,
        clients: list[NetworkClient],
        hostnames: dict[str, str | None],
        network_wireless_clients: int,
        rotation_start_index: int,
        rotation_next_index: int,
    ) -> dict[str, int]:
        """Collect wireless signal quality for selected clients."""
        collected_count = 0
        metric_count = 0
        missing_data_count = 0
        error_count = 0

        for client in clients:
            try:
                self._track_api_call("getNetworkWirelessSignalQualityHistory")
                rate_limiter = getattr(self, "rate_limiter", None)
                if rate_limiter is not None:
                    await rate_limiter.acquire(org_id, "getNetworkWirelessSignalQualityHistory")
                signal_data = await asyncio.to_thread(
                    self.api.wireless.getNetworkWirelessSignalQualityHistory,
                    network_id,
                    clientId=client.id,
                    timespan=300,  # 5 minutes as required
                    resolution=300,  # 5 minutes as required
                )
                collected_count += 1

                if not signal_data:
                    missing_data_count += 1
                    logger.debug(
                        "No signal quality data returned",
                        client_id=client.id,
                        network_id=network_id,
                    )
                    continue

                # Get the most recent data point
                latest_data = signal_data[-1] if signal_data else None

                if not latest_data:
                    missing_data_count += 1
                    continue

                # Extract signal quality values
                rssi = latest_data.get("rssi")
                snr = latest_data.get("snr")

                if rssi is None and snr is None:
                    missing_data_count += 1
                    logger.debug(
                        "No RSSI or SNR data in response",
                        client_id=client.id,
                    )
                    continue

                # Get resolved hostname
                resolved_hostname = hostnames.get(client.ip) if client.ip else None
                hostname = self._determine_hostname(client, resolved_hostname)

                # Sanitize label values
                sanitized_hostname = self._sanitize_label_value(hostname)
                sanitized_description = self._sanitize_label_value(client.description)

                # Create client labels using helper
                client_data = {
                    "id": client.id,
                    "mac": client.mac,
                    "description": sanitized_description,
                    "hostname": sanitized_hostname,
                }
                labels = create_client_labels(
                    client_data,
                    org_id=org_id,
                    org_name=org_name,
                    network_id=network_id,
                    network_name=network_name,
                    ssid=client.ssid or "Unknown",
                    **self._create_recent_ap_labels(client),
                )

                # Set metrics
                if rssi is not None:
                    self.wireless_client_rssi.labels(**labels).set(float(rssi))
                    metric_count += 1

                if snr is not None:
                    self.wireless_client_snr.labels(**labels).set(float(snr))
                    metric_count += 1

                logger.debug(
                    "Set wireless signal quality metrics",
                    client_id=client.id,
                    rssi=rssi,
                    snr=snr,
                    ssid=client.ssid,
                )

            except Exception as e:
                error_count += 1
                logger.error(
                    "Failed to fetch signal quality for client",
                    client_id=client.id,
                    network_id=network_id,
                    error=str(e),
                )
                self._track_error(ErrorCategory.API_CLIENT_ERROR)
                # Continue with next client
                continue

        logger.info(
            "Completed wireless signal quality collection",
            network_id=network_id,
            network_name=network_name,
            network_wireless_clients=network_wireless_clients,
            network_signal_quality_limit=len(clients),
            signal_quality_collected_count=collected_count,
            signal_quality_metric_count=metric_count,
            signal_quality_missing_data_count=missing_data_count,
            signal_quality_error_count=error_count,
            rotation_start_index=rotation_start_index,
            rotation_next_index=rotation_next_index,
        )
        return {
            "collected_count": collected_count,
            "metric_count": metric_count,
            "missing_data_count": missing_data_count,
            "error_count": error_count,
        }

    def _update_cache_metrics(self) -> None:
        """Update DNS cache and client store metrics."""
        # Get DNS cache statistics
        dns_stats = self.dns_resolver.get_cache_stats()

        # Update DNS cache metrics
        self.dns_cache_total.set(dns_stats["total_entries"])
        self.dns_cache_valid.set(dns_stats["valid_entries"])
        self.dns_cache_expired.set(dns_stats["expired_entries"])

        # Update DNS lookup counters (these are cumulative counters)
        # We need to track the difference since last update
        if self._last_dns_stats is not None:
            # Calculate deltas and increment counters
            total_delta = dns_stats["total_lookups"] - self._last_dns_stats["total_lookups"]
            success_delta = (
                dns_stats["successful_lookups"] - self._last_dns_stats["successful_lookups"]
            )
            failed_delta = dns_stats["failed_lookups"] - self._last_dns_stats["failed_lookups"]
            cached_delta = dns_stats["cache_hits"] - self._last_dns_stats["cache_hits"]

            # Increment counters by the delta using inc()
            if total_delta > 0:
                self.dns_lookups_total.inc(total_delta)
            if success_delta > 0:
                self.dns_lookups_successful.inc(success_delta)
            if failed_delta > 0:
                self.dns_lookups_failed.inc(failed_delta)
            if cached_delta > 0:
                self.dns_lookups_cached.inc(cached_delta)
        else:
            # First run - set initial values by incrementing from 0
            if dns_stats["total_lookups"] > 0:
                self.dns_lookups_total.inc(dns_stats["total_lookups"])
            if dns_stats["successful_lookups"] > 0:
                self.dns_lookups_successful.inc(dns_stats["successful_lookups"])
            if dns_stats["failed_lookups"] > 0:
                self.dns_lookups_failed.inc(dns_stats["failed_lookups"])
            if dns_stats["cache_hits"] > 0:
                self.dns_lookups_cached.inc(dns_stats["cache_hits"])

        # Store current stats for next update
        self._last_dns_stats = dns_stats.copy()

        # Get client store statistics
        store_stats = self.client_store.get_statistics()

        # Update client store metrics
        self.client_store_total.set(store_stats["total_clients"])
        self.client_store_networks.set(store_stats["total_networks"])

        logger.debug(
            "Updated cache metrics",
            dns_cache_total=dns_stats["total_entries"],
            dns_cache_valid=dns_stats["valid_entries"],
            dns_cache_expired=dns_stats["expired_entries"],
            dns_lookups_total=dns_stats["total_lookups"],
            dns_lookups_successful=dns_stats["successful_lookups"],
            dns_lookups_failed=dns_stats["failed_lookups"],
            dns_lookups_cached=dns_stats["cache_hits"],
            client_store_total=store_stats["total_clients"],
            client_store_networks=store_stats["total_networks"],
        )
