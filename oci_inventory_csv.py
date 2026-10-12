#!/usr/bin/env python3
"""OCI multi-region IaaS & PaaS inventory exporter (CSV).

Standalone, read-only script that walks every subscribed region and every
accessible compartment of the tenancy and exports the resources it finds to
CSV files. Only OCI SDK ``list_*`` / ``get_*`` calls are used; nothing is ever
created, changed or deleted.

Authentication reuses your existing OCI CLI / API-key setup (``~/.oci/config``).

Usage:
    pip install oci
    python3 oci_inventory_csv.py                       # all regions, all compartments
    python3 oci_inventory_csv.py --profile PROD
    python3 oci_inventory_csv.py --regions us-ashburn-1,uk-london-1
    python3 oci_inventory_csv.py --compartment ocid1.compartment.oc1..xxxx
    python3 oci_inventory_csv.py --output-dir ./inventory --workers 16

Output (in ``<output-dir>/oci_inventory_<timestamp>/``):
    OCI_Inventory_All.csv        one row per resource, common columns
    OCI_Inventory_Summary.csv    resource counts per region / service / type
    OCI_Inventory_Errors.csv     calls that failed (permissions, service not
                                 available in region, ...)
    OCI_Resource_Search.csv      everything OCI Resource Search can see, as a
                                 completeness cross-check (skip: --no-search)
    <Category>_<Service>_<Type>.csv
                                 one file per resource type with every
                                 attribute returned by the API, flattened
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import re
import sys
import threading
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

try:
    import oci
except ImportError:  # pragma: no cover
    sys.exit("The OCI Python SDK is required:  pip install oci")

log = logging.getLogger("oci_inventory")

SKIP_STATES = {"TERMINATED", "DELETED"}
MAX_CELL_LEN = 32000  # stay under Excel's 32,767 character cell limit

# ---------------------------------------------------------------------------
# Resource catalogue
# ---------------------------------------------------------------------------
# scope:
#   comp    list_x(compartment_id=<compartment>)
#   ad      list_x(compartment_id=<compartment>, availability_domain=<ad>) per AD
#   ns      list_x(namespace_name=<ns>, compartment_id=<compartment>)
#   tenancy list_x(compartment_id=<tenancy>) once (root only)
# home_only: global (IAM) resources, listed only in the home region.
# children: listed for each parent row; kwargs values are formatted with the
#   parent's fields, e.g. {"application_id": "{id}"}.


def R(category, service, rtype, client, method, scope="comp", home_only=False,
      kwargs=None, children=None):
    return {
        "category": category, "service": service, "type": rtype,
        "client": client, "method": method, "scope": scope,
        "home_only": home_only, "kwargs": kwargs or {}, "children": children or [],
    }


def C(rtype, client, method, kwargs):
    """Child resource listed once per parent row."""
    return {"type": rtype, "client": client, "method": method, "kwargs": kwargs}


RESOURCES = [
    # ----------------------------- IaaS ----------------------------------
    # Compute
    R("IaaS", "Compute", "Instance", "core.ComputeClient", "list_instances"),
    R("IaaS", "Compute", "Custom Image", "core.ComputeClient", "list_images"),
    R("IaaS", "Compute", "Dedicated VM Host", "core.ComputeClient", "list_dedicated_vm_hosts"),
    R("IaaS", "Compute", "Capacity Reservation", "core.ComputeClient", "list_compute_capacity_reservations"),
    R("IaaS", "Compute", "VNIC Attachment", "core.ComputeClient", "list_vnic_attachments"),
    R("IaaS", "Compute", "Volume Attachment", "core.ComputeClient", "list_volume_attachments"),
    R("IaaS", "Compute", "Boot Volume Attachment", "core.ComputeClient", "list_boot_volume_attachments", scope="ad"),
    R("IaaS", "Compute", "Instance Configuration", "core.ComputeManagementClient", "list_instance_configurations"),
    R("IaaS", "Compute", "Instance Pool", "core.ComputeManagementClient", "list_instance_pools"),
    R("IaaS", "Compute", "Cluster Network", "core.ComputeManagementClient", "list_cluster_networks"),
    R("IaaS", "Compute", "Autoscaling Configuration", "autoscaling.AutoScalingClient", "list_auto_scaling_configurations"),
    # Block storage
    R("IaaS", "Block Storage", "Block Volume", "core.BlockstorageClient", "list_volumes"),
    R("IaaS", "Block Storage", "Boot Volume", "core.BlockstorageClient", "list_boot_volumes"),
    R("IaaS", "Block Storage", "Volume Backup", "core.BlockstorageClient", "list_volume_backups"),
    R("IaaS", "Block Storage", "Boot Volume Backup", "core.BlockstorageClient", "list_boot_volume_backups"),
    R("IaaS", "Block Storage", "Volume Group", "core.BlockstorageClient", "list_volume_groups"),
    R("IaaS", "Block Storage", "Volume Group Backup", "core.BlockstorageClient", "list_volume_group_backups"),
    R("IaaS", "Block Storage", "Backup Policy", "core.BlockstorageClient", "list_volume_backup_policies"),
    # File & object storage
    R("IaaS", "File Storage", "File System", "file_storage.FileStorageClient", "list_file_systems", scope="ad"),
    R("IaaS", "File Storage", "Mount Target", "file_storage.FileStorageClient", "list_mount_targets", scope="ad"),
    R("IaaS", "File Storage", "Export Set", "file_storage.FileStorageClient", "list_export_sets", scope="ad"),
    R("IaaS", "Object Storage", "Bucket", "object_storage.ObjectStorageClient", "list_buckets", scope="ns",
      kwargs={"fields": ["tags"]}),
    # Networking
    R("IaaS", "Networking", "VCN", "core.VirtualNetworkClient", "list_vcns"),
    R("IaaS", "Networking", "Subnet", "core.VirtualNetworkClient", "list_subnets"),
    R("IaaS", "Networking", "Route Table", "core.VirtualNetworkClient", "list_route_tables"),
    R("IaaS", "Networking", "Security List", "core.VirtualNetworkClient", "list_security_lists"),
    R("IaaS", "Networking", "Network Security Group", "core.VirtualNetworkClient", "list_network_security_groups",
      children=[C("NSG Security Rule", "core.VirtualNetworkClient", "list_network_security_group_security_rules",
                  {"network_security_group_id": "{id}"})]),
    R("IaaS", "Networking", "DHCP Options", "core.VirtualNetworkClient", "list_dhcp_options"),
    R("IaaS", "Networking", "Internet Gateway", "core.VirtualNetworkClient", "list_internet_gateways"),
    R("IaaS", "Networking", "NAT Gateway", "core.VirtualNetworkClient", "list_nat_gateways"),
    R("IaaS", "Networking", "Service Gateway", "core.VirtualNetworkClient", "list_service_gateways"),
    R("IaaS", "Networking", "Local Peering Gateway", "core.VirtualNetworkClient", "list_local_peering_gateways"),
    R("IaaS", "Networking", "DRG", "core.VirtualNetworkClient", "list_drgs"),
    R("IaaS", "Networking", "DRG Attachment", "core.VirtualNetworkClient", "list_drg_attachments"),
    R("IaaS", "Networking", "Remote Peering Connection", "core.VirtualNetworkClient", "list_remote_peering_connections"),
    R("IaaS", "Networking", "Reserved Public IP", "core.VirtualNetworkClient", "list_public_ips",
      kwargs={"scope": "REGION", "lifetime": "RESERVED"}),
    R("IaaS", "Networking", "CPE", "core.VirtualNetworkClient", "list_cpes"),
    R("IaaS", "Networking", "IPSec Connection", "core.VirtualNetworkClient", "list_ip_sec_connections"),
    R("IaaS", "Networking", "FastConnect Virtual Circuit", "core.VirtualNetworkClient", "list_virtual_circuits"),
    R("IaaS", "Networking", "FastConnect Cross Connect", "core.VirtualNetworkClient", "list_cross_connects"),
    R("IaaS", "Networking", "Load Balancer", "load_balancer.LoadBalancerClient", "list_load_balancers"),
    R("IaaS", "Networking", "Network Load Balancer", "network_load_balancer.NetworkLoadBalancerClient",
      "list_network_load_balancers"),
    R("IaaS", "Networking", "DNS Zone", "dns.DnsClient", "list_zones"),
    R("IaaS", "Networking", "DNS Steering Policy", "dns.DnsClient", "list_steering_policies"),
    R("IaaS", "Networking", "Network Firewall", "network_firewall.NetworkFirewallClient", "list_network_firewalls"),
    R("IaaS", "Networking", "Network Firewall Policy", "network_firewall.NetworkFirewallClient",
      "list_network_firewall_policies"),
    # Security
    R("IaaS", "Security", "WAF Web App Firewall", "waf.WafClient", "list_web_app_firewalls"),
    R("IaaS", "Security", "WAF Policy", "waf.WafClient", "list_web_app_firewall_policies"),
    R("IaaS", "Security", "Vault", "key_management.KmsVaultClient", "list_vaults"),
    R("IaaS", "Security", "Secret", "vault.VaultsClient", "list_secrets"),
    R("IaaS", "Security", "Certificate", "certificates_management.CertificatesManagementClient", "list_certificates"),
    R("IaaS", "Security", "Bastion", "bastion.BastionClient", "list_bastions"),
    # Observability & management
    R("IaaS", "Observability", "Log Group", "logging.LoggingManagementClient", "list_log_groups"),
    R("IaaS", "Observability", "Alarm", "monitoring.MonitoringClient", "list_alarms"),
    R("IaaS", "Observability", "Notification Topic", "ons.NotificationControlPlaneClient", "list_topics"),
    R("IaaS", "Observability", "Event Rule", "events.EventsClient", "list_rules"),
    # Identity (global - home region only)
    R("IaaS", "Identity", "Compartment", "identity.IdentityClient", "list_compartments", home_only=True),
    R("IaaS", "Identity", "Policy", "identity.IdentityClient", "list_policies", home_only=True),
    R("IaaS", "Identity", "Tag Namespace", "identity.IdentityClient", "list_tag_namespaces", home_only=True),
    R("IaaS", "Identity", "Identity Domain", "identity.IdentityClient", "list_domains", home_only=True),
    R("IaaS", "Identity", "User", "identity.IdentityClient", "list_users", scope="tenancy", home_only=True),
    R("IaaS", "Identity", "Group", "identity.IdentityClient", "list_groups", scope="tenancy", home_only=True),
    R("IaaS", "Identity", "Dynamic Group", "identity.IdentityClient", "list_dynamic_groups", scope="tenancy",
      home_only=True),

    # ----------------------------- PaaS ----------------------------------
    # Oracle Database
    R("PaaS", "Database", "DB System", "database.DatabaseClient", "list_db_systems"),
    R("PaaS", "Database", "DB Home", "database.DatabaseClient", "list_db_homes",
      children=[C("Database", "database.DatabaseClient", "list_databases",
                  {"compartment_id": "{compartment_id}", "db_home_id": "{id}"})]),
    R("PaaS", "Database", "Autonomous Database", "database.DatabaseClient", "list_autonomous_databases"),
    R("PaaS", "Database", "Autonomous Container Database", "database.DatabaseClient",
      "list_autonomous_container_databases"),
    R("PaaS", "Database", "Cloud Exadata Infrastructure", "database.DatabaseClient",
      "list_cloud_exadata_infrastructures"),
    R("PaaS", "Database", "Cloud VM Cluster", "database.DatabaseClient", "list_cloud_vm_clusters"),
    R("PaaS", "Database", "Cloud Autonomous VM Cluster", "database.DatabaseClient",
      "list_cloud_autonomous_vm_clusters"),
    R("PaaS", "Database", "Exadata Database Service VM Cluster", "database.DatabaseClient", "list_exadb_vm_clusters"),
    R("PaaS", "MySQL HeatWave", "MySQL DB System", "mysql.DbSystemClient", "list_db_systems"),
    R("PaaS", "MySQL HeatWave", "MySQL Backup", "mysql.DbBackupsClient", "list_backups"),
    R("PaaS", "PostgreSQL", "PostgreSQL DB System", "psql.PostgresqlClient", "list_db_systems"),
    R("PaaS", "NoSQL", "NoSQL Table", "nosql.NosqlClient", "list_tables"),
    R("PaaS", "Cache", "Redis Cluster", "redis.RedisClusterClient", "list_redis_clusters"),
    R("PaaS", "Search", "OpenSearch Cluster", "opensearch.OpensearchClusterClient", "list_opensearch_clusters"),
    R("PaaS", "GoldenGate", "GoldenGate Deployment", "golden_gate.GoldenGateClient", "list_deployments"),
    # Containers & serverless
    R("PaaS", "Kubernetes (OKE)", "OKE Cluster", "container_engine.ContainerEngineClient", "list_clusters"),
    R("PaaS", "Kubernetes (OKE)", "OKE Node Pool", "container_engine.ContainerEngineClient", "list_node_pools"),
    R("PaaS", "Kubernetes (OKE)", "OKE Virtual Node Pool", "container_engine.ContainerEngineClient",
      "list_virtual_node_pools"),
    R("PaaS", "Container Instances", "Container Instance", "container_instances.ContainerInstanceClient",
      "list_container_instances"),
    R("PaaS", "Container Registry", "Container Repository", "artifacts.ArtifactsClient",
      "list_container_repositories"),
    R("PaaS", "Artifact Registry", "Artifact Repository", "artifacts.ArtifactsClient", "list_repositories"),
    R("PaaS", "Functions", "Functions Application", "functions.FunctionsManagementClient", "list_applications",
      children=[C("Function", "functions.FunctionsManagementClient", "list_functions",
                  {"application_id": "{id}"})]),
    R("PaaS", "API Gateway", "API Gateway", "apigateway.GatewayClient", "list_gateways"),
    R("PaaS", "API Gateway", "API Deployment", "apigateway.DeploymentClient", "list_deployments"),
    # Integration, analytics & AI
    R("PaaS", "Integration", "Integration Instance", "integration.IntegrationInstanceClient",
      "list_integration_instances"),
    R("PaaS", "Visual Builder", "Visual Builder Instance", "visual_builder.VbInstanceClient", "list_vb_instances"),
    R("PaaS", "Analytics", "Analytics Instance", "analytics.AnalyticsClient", "list_analytics_instances"),
    R("PaaS", "Digital Assistant", "Digital Assistant Instance", "oda.OdaClient", "list_oda_instances"),
    R("PaaS", "Data Science", "Data Science Project", "data_science.DataScienceClient", "list_projects"),
    R("PaaS", "Data Science", "Notebook Session", "data_science.DataScienceClient", "list_notebook_sessions"),
    R("PaaS", "Data Science", "Model Deployment", "data_science.DataScienceClient", "list_model_deployments"),
    R("PaaS", "Data Flow", "Data Flow Application", "data_flow.DataFlowClient", "list_applications"),
    R("PaaS", "Data Integration", "Data Integration Workspace", "data_integration.DataIntegrationClient",
      "list_workspaces"),
    R("PaaS", "Data Catalog", "Data Catalog", "data_catalog.DataCatalogClient", "list_catalogs"),
    R("PaaS", "Big Data", "Big Data Service Cluster", "bds.BdsClient", "list_bds_instances"),
    R("PaaS", "Generative AI", "Dedicated AI Cluster", "generative_ai.GenerativeAiClient",
      "list_dedicated_ai_clusters"),
    R("PaaS", "Generative AI", "Generative AI Endpoint", "generative_ai.GenerativeAiClient", "list_endpoints"),
    # Messaging & application services
    R("PaaS", "Streaming", "Stream Pool", "streaming.StreamAdminClient", "list_stream_pools"),
    R("PaaS", "Streaming", "Stream", "streaming.StreamAdminClient", "list_streams"),
    R("PaaS", "Queue", "Queue", "queue.QueueAdminClient", "list_queues"),
    R("PaaS", "Email Delivery", "Approved Sender", "email.EmailClient", "list_senders"),
    R("PaaS", "Blockchain", "Blockchain Platform", "blockchain.BlockchainPlatformClient",
      "list_blockchain_platforms"),
    R("PaaS", "APM", "APM Domain", "apm_control_plane.ApmDomainClient", "list_apm_domains"),
    R("PaaS", "DevOps", "DevOps Project", "devops.DevopsClient", "list_projects"),
    R("PaaS", "Resource Manager", "Resource Manager Stack", "resource_manager.ResourceManagerClient", "list_stacks"),
]

COMMON_COLUMNS = [
    "Region", "Category", "Service", "Resource Type", "Compartment Name", "Compartment Path",
    "Name", "OCID", "Lifecycle State", "Availability Domain", "Shape", "Time Created",
    "Parent OCID", "Freeform Tags", "Defined Tags",
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class Inventory:
    """Thread-safe store for rows and errors, plus a per-thread client cache."""

    def __init__(self, config: dict, timeout: tuple[int, int]):
        self.config = config
        self.timeout = timeout
        self.rows: dict[tuple[str, str, str], list[dict]] = defaultdict(list)
        self.errors: list[dict] = []
        self._lock = threading.Lock()
        self._local = threading.local()

    def client(self, path: str, region: str):
        cache = getattr(self._local, "clients", None)
        if cache is None:
            cache = self._local.clients = {}
        key = (path, region)
        if key not in cache:
            module_name, class_name = path.split(".")
            cls = getattr(getattr(oci, module_name), class_name)
            cfg = dict(self.config, region=region)
            cache[key] = cls(cfg, retry_strategy=oci.retry.DEFAULT_RETRY_STRATEGY, timeout=self.timeout)
        return cache[key]

    def add(self, key, rows):
        with self._lock:
            self.rows[key].extend(rows)

    def error(self, region, spec_type, compartment, exc):
        status = getattr(exc, "status", "")
        code = getattr(exc, "code", type(exc).__name__)
        message = getattr(exc, "message", None) or str(exc)
        with self._lock:
            self.errors.append({
                "Region": region, "Resource Type": spec_type, "Compartment": compartment,
                "Status": status, "Code": code, "Message": message[:500],
            })


def list_all(client, method: str, **kwargs) -> list:
    fn = getattr(client, method)
    return oci.pagination.list_call_get_all_results(fn, **kwargs).data


def flatten(value, prefix="", out=None) -> dict:
    """Flatten nested dicts to dotted keys; lists become JSON strings."""
    if out is None:
        out = {}
    if isinstance(value, dict):
        for k, v in value.items():
            flatten(v, f"{prefix}.{k}" if prefix else str(k), out)
    elif isinstance(value, (list, tuple)):
        out[prefix] = json.dumps(value, default=str) if value else ""
    else:
        out[prefix] = "" if value is None else value
    return out


def to_json(value) -> str:
    return json.dumps(value, default=str, sort_keys=True) if value else ""


def build_row(item, spec, region, comp, parent_id="") -> dict:
    data = oci.util.to_dict(item)
    if not isinstance(data, dict):
        data = {"value": data}
    shape = data.get("shape") or data.get("node_shape") or data.get("db_system_shape") or data.get("shape_name")
    row = {
        "Region": region,
        "Category": spec["category"],
        "Service": spec["service"],
        "Resource Type": spec["type"],
        "Compartment Name": comp["name"],
        "Compartment Path": comp["path"],
        "Name": data.get("display_name") or data.get("name") or data.get("db_name") or data.get("email_address") or "",
        "OCID": data.get("id") or "",
        "Lifecycle State": data.get("lifecycle_state") or data.get("state") or data.get("status") or "",
        "Availability Domain": data.get("availability_domain") or "",
        "Shape": shape if isinstance(shape, str) else "",
        "Time Created": data.get("time_created") or "",
        "Parent OCID": parent_id,
        "Freeform Tags": to_json(data.get("freeform_tags")),
        "Defined Tags": to_json(data.get("defined_tags")),
    }
    detail = flatten({k: v for k, v in data.items() if k not in ("freeform_tags", "defined_tags", "system_tags")})
    for k, v in detail.items():
        if k.endswith("user_data"):  # cloud-init scripts can embed secrets
            continue
        row.setdefault(f"attr.{k}", v)
    row["_compartment_id"] = data.get("compartment_id") or ""
    return row


def keep(row, include_deleted: bool) -> bool:
    return include_deleted or str(row["Lifecycle State"]).upper() not in SKIP_STATES


def safe_name(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", text).strip("_")


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def get_compartments(identity, tenancy_id: str, only: str | None) -> list[dict]:
    tenancy = identity.get_compartment(tenancy_id).data
    items = list_all(identity, "list_compartments", compartment_id=tenancy_id,
                     compartment_id_in_subtree=True, access_level="ACCESSIBLE", lifecycle_state="ACTIVE")
    by_id = {tenancy_id: {"id": tenancy_id, "name": f"{tenancy.name} (root)", "parent": None}}
    for c in items:
        by_id[c.id] = {"id": c.id, "name": c.name, "parent": c.compartment_id}

    def path(cid):
        parts, seen = [], set()
        while cid in by_id and cid not in seen:
            seen.add(cid)
            parts.append(by_id[cid]["name"])
            cid = by_id[cid]["parent"]
        return " / ".join(reversed(parts))

    comps = [{"id": c["id"], "name": c["name"], "path": path(c["id"])} for c in by_id.values()]
    if only:
        # The selected compartment plus all of its sub-compartments.
        wanted = {only}
        changed = True
        while changed:
            changed = False
            for c in by_id.values():
                if c["parent"] in wanted and c["id"] not in wanted:
                    wanted.add(c["id"])
                    changed = True
        comps = [c for c in comps if c["id"] in wanted]
        if not comps:
            raise SystemExit(f"Compartment {only} not found or not accessible.")
    return sorted(comps, key=lambda c: c["path"])


def get_regions(identity, tenancy_id: str, only: list[str] | None) -> tuple[list[str], str]:
    subs = identity.list_region_subscriptions(tenancy_id).data
    home = next((s.region_name for s in subs if s.is_home_region), subs[0].region_name)
    regions = sorted(s.region_name for s in subs if s.status == "READY")
    if only:
        unknown = set(only) - set(regions)
        if unknown:
            log.warning("Not subscribed / unknown regions ignored: %s", ", ".join(sorted(unknown)))
        regions = [r for r in regions if r in only]
    return regions, home


# ---------------------------------------------------------------------------
# Collection
# ---------------------------------------------------------------------------


def collect_task(inv: Inventory, spec, region, comp, ctx, include_deleted) -> int:
    """List one resource type in one compartment/region (and its children)."""
    key = (spec["category"], spec["service"], spec["type"])
    try:
        client = inv.client(spec["client"], region)
        kwargs = dict(spec["kwargs"])
        scope = spec["scope"]
        items = []
        if scope == "ad":
            for ad in ctx["ads"].get(region, []):
                items += list_all(client, spec["method"], compartment_id=comp["id"], availability_domain=ad, **kwargs)
        elif scope == "ns":
            items = list_all(client, spec["method"], namespace_name=ctx["namespace"], compartment_id=comp["id"],
                             **kwargs)
        else:
            items = list_all(client, spec["method"], compartment_id=comp["id"], **kwargs)
    except Exception as exc:  # noqa: BLE001 - one failure must never stop the run
        inv.error(region, spec["type"], comp["path"], exc)
        return 0

    rows = []
    for item in items:
        row = build_row(item, spec, region if not spec["home_only"] else f"{region} (global)", comp)
        # Some list APIs (e.g. images) also return objects from other compartments.
        if row["_compartment_id"] and row["_compartment_id"] != comp["id"] and spec["type"] != "Compartment":
            continue
        if keep(row, include_deleted):
            rows.append(row)
    inv.add(key, rows)
    count = len(rows)

    for child in spec["children"]:
        child_spec = dict(spec, type=child["type"], children=[])
        child_key = (spec["category"], spec["service"], child["type"])
        child_client = inv.client(child["client"], region)
        for parent in rows:
            fields = {"id": parent["OCID"], "compartment_id": comp["id"]}
            kwargs = {k: v.format(**fields) for k, v in child["kwargs"].items()}
            try:
                child_items = list_all(child_client, child["method"], **kwargs)
            except Exception as exc:  # noqa: BLE001
                inv.error(region, child["type"], comp["path"], exc)
                continue
            child_rows = [build_row(i, child_spec, parent["Region"], comp, parent_id=parent["OCID"])
                          for i in child_items]
            child_rows = [r for r in child_rows if keep(r, include_deleted)]
            inv.add(child_key, child_rows)
            count += len(child_rows)
    return count


def resource_search(inv: Inventory, regions, comps_by_id, include_deleted) -> list[dict]:
    """Cross-check: every resource OCI Resource Search knows about, per region."""
    details = oci.resource_search.models.StructuredSearchDetails(
        type="Structured", query="query all resources", matching_context_type="NONE")
    rows = []
    for region in regions:
        try:
            client = inv.client("resource_search.ResourceSearchClient", region)
            items = list_all(client, "search_resources", search_details=details)
        except Exception as exc:  # noqa: BLE001
            inv.error(region, "Resource Search", "", exc)
            continue
        for i in items:
            state = (i.lifecycle_state or "").upper()
            if not include_deleted and state in SKIP_STATES:
                continue
            comp = comps_by_id.get(i.compartment_id)
            if comps_by_id and i.compartment_id and comp is None:
                continue  # outside the selected compartment tree
            rows.append({
                "Region": region,
                "Resource Type": i.resource_type,
                "Name": i.display_name or "",
                "OCID": i.identifier,
                "Lifecycle State": i.lifecycle_state or "",
                "Availability Domain": i.availability_domain or "",
                "Compartment Name": comp["name"] if comp else "",
                "Compartment Path": comp["path"] if comp else "",
                "Time Created": i.time_created or "",
                "Freeform Tags": to_json(i.freeform_tags),
                "Defined Tags": to_json(i.defined_tags),
            })
        log.info("Resource Search %-20s %6d resources", region, sum(1 for r in rows if r["Region"] == region))
    return rows


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def clip(value):
    if isinstance(value, str) and len(value) > MAX_CELL_LEN:
        return value[:MAX_CELL_LEN] + "...[truncated]"
    return value


def write_csv(path: Path, rows: list[dict], columns: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({c: clip(row.get(c, "")) for c in columns})


def write_outputs(inv: Inventory, out_dir: Path, search_rows: list[dict] | None) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    all_rows = []
    summary = Counter()
    for (category, service, rtype), rows in sorted(inv.rows.items()):
        if not rows:
            continue
        all_rows.extend(rows)
        for r in rows:
            summary[(r["Region"], category, service, rtype)] += 1
        extra = sorted({k for r in rows for k in r if k.startswith("attr.")})
        write_csv(out_dir / f"{category}_{safe_name(service)}_{safe_name(rtype)}.csv", rows, COMMON_COLUMNS + extra)

    write_csv(out_dir / "OCI_Inventory_All.csv", all_rows, COMMON_COLUMNS)
    write_csv(
        out_dir / "OCI_Inventory_Summary.csv",
        [{"Region": k[0], "Category": k[1], "Service": k[2], "Resource Type": k[3], "Count": v}
         for k, v in sorted(summary.items())],
        ["Region", "Category", "Service", "Resource Type", "Count"],
    )
    write_csv(out_dir / "OCI_Inventory_Errors.csv", inv.errors,
              ["Region", "Resource Type", "Compartment", "Status", "Code", "Message"])
    if search_rows is not None:
        write_csv(out_dir / "OCI_Resource_Search.csv", search_rows,
                  ["Region", "Resource Type", "Name", "OCID", "Lifecycle State", "Availability Domain",
                   "Compartment Name", "Compartment Path", "Time Created", "Freeform Tags", "Defined Tags"])
    log.info("Total resources: %d   (%d resource types)", len(all_rows), sum(1 for r in inv.rows.values() if r))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Export OCI IaaS & PaaS inventory for all regions to CSV (read-only).")
    p.add_argument("--config-file", default=os.getenv("OCI_CLI_CONFIG_FILE", oci.config.DEFAULT_LOCATION),
                   help="OCI config file (default: ~/.oci/config)")
    p.add_argument("--profile", default=os.getenv("OCI_CLI_PROFILE", "DEFAULT"), help="OCI config profile")
    p.add_argument("--regions", help="Comma-separated regions to scan (default: all subscribed regions)")
    p.add_argument("--compartment", help="Only scan this compartment OCID and its sub-compartments")
    p.add_argument("--output-dir", default="./output", help="Base output directory (default: ./output)")
    p.add_argument("--workers", type=int, default=10, help="Parallel API workers (default: 10)")
    p.add_argument("--include-deleted", action="store_true", help="Also export TERMINATED/DELETED resources")
    p.add_argument("--no-search", action="store_true", help="Skip the OCI Resource Search cross-check CSV")
    p.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(message)s", datefmt="%H:%M:%S")
    if not args.verbose:
        logging.getLogger("oci").setLevel(logging.WARNING)

    config = oci.config.from_file(os.path.expanduser(args.config_file), args.profile)
    oci.config.validate_config(config)
    tenancy_id = config["tenancy"]
    inv = Inventory(config, timeout=(10, 120))

    identity = inv.client("identity.IdentityClient", config["region"])
    regions, home = get_regions(identity, tenancy_id, args.regions.split(",") if args.regions else None)
    identity = inv.client("identity.IdentityClient", home)
    comps = get_compartments(identity, tenancy_id, args.compartment)
    log.info("Tenancy: %s | Home region: %s", tenancy_id, home)
    log.info("Regions (%d): %s", len(regions), ", ".join(regions))
    log.info("Compartments: %d", len(comps))

    ctx = {"ads": {}, "namespace": None}
    try:
        ctx["namespace"] = inv.client("object_storage.ObjectStorageClient", home).get_namespace().data
    except Exception as exc:  # noqa: BLE001
        inv.error(home, "Object Storage Namespace", "", exc)
    for region in regions:
        try:
            ads = inv.client("identity.IdentityClient", region).list_availability_domains(tenancy_id).data
            ctx["ads"][region] = [ad.name for ad in ads]
        except Exception as exc:  # noqa: BLE001
            inv.error(region, "Availability Domains", "", exc)

    tasks = []
    root = [c for c in comps if c["id"] == tenancy_id]  # empty when --compartment is used
    for spec in RESOURCES:
        if spec["scope"] == "ns" and not ctx["namespace"]:
            continue
        spec_regions = [home] if spec["home_only"] else regions
        spec_comps = root if spec["scope"] == "tenancy" else comps
        for region in spec_regions:
            for comp in spec_comps:
                tasks.append((spec, region, comp))

    log.info("Running %d list operations with %d workers ...", len(tasks), args.workers)
    started = time.time()
    done = 0
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        futures = {pool.submit(collect_task, inv, s, r, c, ctx, args.include_deleted): (s, r, c)
                   for s, r, c in tasks}
        for fut in as_completed(futures):
            done += 1
            spec, region, comp = futures[fut]
            found = fut.result()
            if found:
                log.debug("%-16s %-35s %-40s %d", region, spec["type"], comp["path"], found)
            if done % 250 == 0 or done == len(tasks):
                log.info("Progress: %d/%d operations (%.0fs)", done, len(tasks), time.time() - started)

    search_rows = None
    if not args.no_search:
        comps_by_id = {c["id"]: c for c in comps}
        search_rows = resource_search(inv, regions, comps_by_id, args.include_deleted)

    out_dir = Path(args.output_dir) / f"oci_inventory_{datetime.now():%Y%m%d_%H%M%S}"
    write_outputs(inv, out_dir, search_rows)
    log.info("Errors / skipped calls: %d (see OCI_Inventory_Errors.csv)", len(inv.errors))
    log.info("CSV files written to: %s", out_dir.resolve())


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("Interrupted.")
