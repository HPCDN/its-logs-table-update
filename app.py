import os
import json
import datetime as dt
from typing import Iterable, Set, List, Tuple
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from flask import Flask, request, jsonify, abort

from azure.core.exceptions import ResourceExistsError
from azure.storage.blob import BlobServiceClient, ContainerClient
from azure.data.tables import TableClient, TableServiceClient

# ---- load .env for local runs only ----
try:
    from dotenv import load_dotenv, find_dotenv
    # App Service sets WEBSITE_SITE_NAME; if it's missing, we're probably local.
    if not os.environ.get("WEBSITE_SITE_NAME"):
        # Do NOT override existing env (e.g., real secrets or CI vars)
        load_dotenv(find_dotenv(), override=False)
except Exception:
    # If python-dotenv isn't installed or .env missing, just continue.
    pass

# ------------------ Helpers ------------------

def _now_in_tz(tzname: str) -> dt:
    try:
        return dt.now(ZoneInfo(tzname))
    except ZoneInfoNotFoundError:
        # fallback to UTC
        print(f"[WARN] Time zone '{tzname}' not found, falling back to UTC")
        return dt.now(ZoneInfo("UTC"))

def _default_dates(now: dt.datetime) -> List[str]:
    yday = now - dt.timedelta(days=1)
    return [now.strftime("%Y/%m/%d"), yday.strftime("%Y/%m/%d")]

def _container_client(blob_cfg: dict) -> ContainerClient:
    """
    Preferred: connection string (blob_cfg["connectionString"]) + container.
    Also supports SAS or MSI if ever needed.
    """
    container = blob_cfg.get("container") or os.environ.get("CONTAINER")
    if not container:
        raise ValueError("blob.container is required")

    mode = (blob_cfg.get("credential") or "connection-string").lower()

    if mode == "connection-string":
        conn = blob_cfg.get("connectionString") or os.environ.get("BLOB_CONNECTION_STRING")
        if not conn:
            raise ValueError("Blob connection string missing (blob.connectionString or BLOB_CONNECTION_STRING).")
        svc = BlobServiceClient.from_connection_string(conn)
        return svc.get_container_client(container)

    if mode == "sas-url":
        sas_url = blob_cfg.get("sasUrl")
        if not sas_url:
            raise ValueError("blob.sasUrl is required for sas-url mode.")
        svc = BlobServiceClient(account_url=sas_url)
        return svc.get_container_client(container)

    # managed-identity fallback
    account_url = blob_cfg.get("accountUrl") or os.environ.get("BLOB_ACCOUNT_URL")
    if not account_url:
        raise ValueError("blob.accountUrl is required for managed-identity mode.")
    svc = BlobServiceClient(account_url=account_url)
    return svc.get_container_client(container)

def _table_client(table_cfg: dict) -> TableClient:
    mode = (table_cfg.get("credential") or "connection-string").lower()
    table_name = table_cfg.get("tableName") or os.environ.get("TABLE_NAME") or "ITSLogs"

    if mode == "managed-identity":
        account_url = table_cfg.get("accountUrl") or os.environ.get("TABLE_ACCOUNT_URL")
        if not account_url:
            raise ValueError("table.accountUrl is required for managed-identity mode.")
        svc = TableServiceClient(endpoint=account_url)
        return svc.get_table_client(table_name=table_name)

    conn = (
        table_cfg.get("connectionString")
        or os.environ.get("TABLE_CONNECTION_STRING")
        or os.environ.get("TABLES_CONNECTION_STRING")
    )
    if not conn:
        raise ValueError("Table connection string missing (table.connectionString or TABLE_CONNECTION_STRING).")
    return TableClient.from_connection_string(conn, table_name=table_name)

def _discover_sources(container: ContainerClient) -> Set[str]:
    sources: Set[str] = set()
    pager = container.list_blobs(name_starts_with="", results_per_page=1000).by_page()
    for page in pager:
        for b in page:
            parts = b.name.split("/", 1)
            if len(parts) >= 2:
                sources.add(parts[0])
        if len(sources) >= 1000:
            break
    return sources

def _iter_with_prefix(container: ContainerClient, prefix: str, suffix: str) -> Iterable[str]:
    for b in container.list_blobs(name_starts_with=prefix):
        if not suffix or b.name.endswith(suffix):
            yield b.name

def _insert_unique(table: TableClient, partition: str, container: str, path: str) -> bool:
    rowkey = path.split("/")[-1]
    entity = {
        "PartitionKey": partition,
        "RowKey": rowkey,
        "Path": f"/{container}/{path}",
        "Status": "pending"
    }
    try:
        table.create_entity(entity=entity)  # 409 if exists
        return True
    except ResourceExistsError:
        return False

def _auth_ok(req) -> Tuple[bool, str]:
    """Optional lightweight auth: set AUTH_TOKEN env and send header X-Auth-Token from Logic App."""
    expected = os.environ.get("AUTH_TOKEN")
    if not expected:
        return True, "auth-disabled"
    got = req.headers.get("X-Auth-Token")
    return (got == expected, "ok" if got == expected else "bad-token")

# ------------------ Flask App ------------------

app = Flask(__name__)
@app.get("/")
def entrypoint():
    return jsonify({"status": "ok", "service": "its-logs-scanner", "time": dt.datetime.utcnow().isoformat()})

@app.get("/health")
def health():
    return jsonify({"status": "ok", "service": "its-logs-scanner", "time": dt.datetime.utcnow().isoformat()})

@app.post("/scan-binzip")
def scan_binzip():
    ok, reason = _auth_ok(request)
    if not ok:
        abort(401, description="Unauthorized")

    try:
        body = request.get_json(silent=True) or {}
        blob_cfg = body.get("blob", {})
        table_cfg = body.get("table", {})
        scan_cfg = body.get("scan", {})
        locale_cfg = body.get("locale", {})

        # Defaults (env)
        blob_cfg.setdefault("credential", "connection-string")
        blob_cfg.setdefault("connectionString", os.environ.get("BLOB_CONNECTION_STRING"))
        blob_cfg.setdefault("container", os.environ.get("CONTAINER", "raw-logs-autoload"))

        table_cfg.setdefault("credential", "connection-string")
        table_cfg.setdefault("connectionString", os.environ.get("TABLE_CONNECTION_STRING") or os.environ.get("TABLES_CONNECTION_STRING"))
        table_cfg.setdefault("tableName", os.environ.get("TABLE_NAME", "ITSLogs"))
        table_cfg.setdefault("partition", os.environ.get("PARTITION", blob_cfg["container"]))

        tzname = locale_cfg.get("timezone") or os.environ.get("LOCAL_TIMEZONE", "Europe/Berlin")
        now = _now_in_tz(tzname)
        dates = scan_cfg.get("dates") or _default_dates(now)
        suffix = scan_cfg.get("suffix", ".bin.zip")

        # Clients
        container_client = _container_client(blob_cfg)
        table_client = _table_client(table_cfg)

        # Sources
        if scan_cfg.get("sources"):
            sources = set(scan_cfg["sources"])
        else:
            sources = _discover_sources(container_client)

        # Scan + insert
        scanned_prefixes = 0
        files_found = 0
        rows_inserted = 0
        rows_skipped = 0

        for source in sorted(sources):
            for d in dates:
                prefix = f"{source}/{d}/"
                scanned_prefixes += 1
                for path in _iter_with_prefix(container_client, prefix, suffix):
                    files_found += 1
                    if _insert_unique(
                        table=table_client,
                        partition=table_cfg["partition"],
                        container=blob_cfg["container"],
                        path=path,
                    ):
                        rows_inserted += 1
                    else:
                        rows_skipped += 1

        return jsonify({
            "effectiveConfig": {
                "blob": {"mode": blob_cfg.get("credential"), "container": blob_cfg["container"]},
                "table": {"mode": table_cfg.get("credential"), "tableName": table_cfg["tableName"], "partition": table_cfg["partition"]},
                "scan": {"sourcesCount": len(sources), "dates": dates, "suffix": suffix},
                "locale": {"timezone": tzname},
                "auth": reason
            },
            "stats": {
                "prefixes_scanned": scanned_prefixes,
                "files_found": files_found,
                "rows_inserted": rows_inserted,
                "rows_skipped_existing": rows_skipped
            },
            "timestamp": now.isoformat()
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)
