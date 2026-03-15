#!/usr/bin/env python3

import argparse
import json
import os
import re
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import BotoCoreError, ClientError


APP_TITLE = "AUTONOMOUS CRM INCIDENT INVESTIGATOR"
INCIDENT_TYPE = "source_volume_drop"

PREP_QUERY_NAME = "inv_prep_recent_vs_hist_volume"
TARGET_TREND_QUERY = "inv_trace_target_volume_trend"
COUNTRY_PEERS_QUERY = "inv_trace_country_peer_volumes"
SOURCE_FAMILY_QUERY = "inv_trace_source_family_peers"
LAST_SEEN_QUERY = "inv_trace_target_last_seen"
RECENT_SAMPLE_QUERY = "inv_trace_recent_target_sample"
INVESTIGATION_SEQUENCE = [
    TARGET_TREND_QUERY,
    COUNTRY_PEERS_QUERY,
    SOURCE_FAMILY_QUERY,
    LAST_SEEN_QUERY,
    RECENT_SAMPLE_QUERY,
]
MATERIAL_DROP_THRESHOLD_PCT = 50.0
DEFAULT_SKIP_REASON = "not needed: earlier evidence sufficient"

REQUIRED_NAMED_QUERIES = [
    PREP_QUERY_NAME,
    TARGET_TREND_QUERY,
    COUNTRY_PEERS_QUERY,
    SOURCE_FAMILY_QUERY,
    LAST_SEEN_QUERY,
    RECENT_SAMPLE_QUERY,
]

ALLOWED_TOOL_QUERY_NAMES = INVESTIGATION_SEQUENCE

DEFAULT_DATABASE = os.getenv("ATHENA_DATABASE", "crm_monitoring_demo")
DEFAULT_ATHENA_OUTPUT = os.getenv(
    "ATHENA_OUTPUT",
    "s3://crm-data-monitoring-demo/athena-results/",
)
DEFAULT_WORKGROUP = os.getenv("ATHENA_WORKGROUP", "primary")
DEFAULT_MODEL_ID = os.getenv("BEDROCK_MODEL_ID", "eu.amazon.nova-pro-v1:0")
DEFAULT_REPORT_FILE = "incident_report.txt"
DEFAULT_LOG_FILE = "investigation_log.json"


NOVA_SYSTEM_PROMPT = """
You are an autonomous CRM data incident investigator.

You are investigating one incident type only: source_volume_drop.

A deterministic detector has already flagged a suspicious group.
Your task is to investigate the flagged incident, not to search the whole dataset.

You must:
1. Verify whether the drop is real and sustained
2. Rule out alternative explanations where possible
3. Identify the most likely explanation
4. Report the evidence clearly

You may use only the named-query investigation tools provided.
Do not ask for additional data.
Do not invent data.
Do not use open-ended SQL logic.

Focus on assessing these explanations using the evidence:
- Normal fluctuation
- Country-wide issue
- Broader multi-country same-source weakness
- Isolated source-specific interruption

=== SESSION MEMORY RULES ===

Apply session memory before deciding which queries to run.
The user prompt will include any already-established source-family findings for the current source family
and any already-established country-level findings for the current country.

RULE 1:
If session memory says inv_trace_source_family_peers already confirmed a broader multi-country
same-source weakness for this source family, do NOT run inv_trace_source_family_peers again.
Record "inv_trace_source_family_peers: session: already established for <source>" in skipped_queries.

RULE 2:
If session memory says inv_trace_country_peer_volumes already ran for this country earlier in this session,
you may skip inv_trace_country_peer_volumes for another source in the same country.
Record "inv_trace_country_peer_volumes: session: already established for <country_code>" in skipped_queries.

=== INVESTIGATION SEQUENCE ===

Use the tools efficiently.
Prefer bounded evidence over speculation.
Run this sequence unless the case is already resolved with fewer steps, or a session-memory rule applies:

1. inv_trace_target_volume_trend
2. inv_trace_country_peer_volumes
3. inv_trace_source_family_peers
4. inv_trace_target_last_seen
5. inv_trace_recent_target_sample (only if needed)

Before moving to the verdict, be explicit about which queries were skipped and why.

=== EVALUATION RULES ===

These rules are mandatory. Apply them mechanically using the data returned by each tool.

THRESHOLD DEFINITION:
- A source is "near baseline" only if its recent volume is above 50% of its historical average.
- A source at or below 50% of its historical average is a "material drop."
- Use the recent_vs_historical percentage field for this comparison, not raw recent volume.

COUNTRY-PEER EVALUATION (inv_trace_country_peer_volumes):
- If most peer sources in the same country are near baseline, the country is not experiencing a country-wide issue.
- If multiple peer sources also show material drops, the evidence supports a country-wide issue.
- You must cite at least two specific peer values (source name and their recent_vs_historical %)
  when making this ruling.

SOURCE-FAMILY EVALUATION (inv_trace_source_family_peers):
- If ANY peer country for the same source family shows a material drop (at or below 50%),
  you CANNOT rule out broader multi-country same-source weakness.
- To rule out broader multi-country weakness, ALL peer countries must be near baseline (above 50%).
- You must cite at least two specific peer values (country and their recent_vs_historical %)
  when making this ruling.
- Do not describe peers as "near or above baseline" without verifying each peer's percentage individually.

RULING-OUT CONSTRAINTS:
- Do not claim "others are fine" unless the peer data clearly shows they are near baseline per the threshold above.
- If peer data shows material drops in the same source family across countries, treat that as evidence OF a broader pattern, not against it.
- If evidence is mixed or ambiguous, say so explicitly. Do not force a clean ruling.

CROSS-EXPLANATION CONSISTENCY:
- If you identify a broader multi-country same-source weakness, the most likely explanation
  must reflect that pattern, not "isolated source-specific interruption."
- An isolated source-specific interruption requires that source-family peers in other countries are near baseline.

=== OUTPUT FORMAT ===

Output exactly this JSON structure and nothing else. Do not use markdown blocks.

{
  "group": "<country_code | source>",
  "country_code": "<country_code>",
  "source": "<source>",
  "verdict": "<confirmed | ruled_out>",
  "pattern": "<Isolated source-specific interruption | Broader multi-country same-source weakness | Country-wide issue>",
  "hist_avg": <number>,
  "recent_avg": <number>,
  "last_3d_rows": <number>,
  "recent_vs_hist_pct": <number or null>,
  "last_seen": "<timestamp or null>",
  "skipped_queries": ["<query_name: reason>"],
  "summary": "<one concise sentence>",
  "most_likely_explanation": "<bounded, specific sentence>",
  "impact": "<concrete operational sentence>"
}

- skipped_queries must always be present. Use an empty list [] if nothing was skipped.
If a field is unavailable, write null.
Use the exact group format: country_code | source.
If the incident is ruled out, still fill the report honestly.
If evidence is unavailable, say so honestly instead of inventing support.

The summary must be concise and must not repeat the impact line.
The impact must describe the operational effect using the numbers already available.
The most likely explanation must be specific but clearly framed as likely, not certain.
Do not give unsupported root-cause certainty.

A confirmed verdict means the evidence supports a real sustained drop. It does not require isolation.
If the target is part of a broader pattern, say that clearly in most_likely_explanation.
""".strip()


RUN_NAMED_QUERY_DESCRIPTION = """
Run one bounded Athena named query for the flagged country_code + source.

Valid query_name values:
- inv_trace_target_volume_trend: Daily volume for the target group over the last 7 days, plus historical baseline metrics. Use this first to confirm whether the drop is real and sustained.
- inv_trace_country_peer_volumes: Same-country peer source comparison including historical average, recent average, last-3d rows, and recent-vs-historical %. Use this to assess whether the target looks isolated or whether the whole country is weakened.
- inv_trace_source_family_peers: Same source family across countries including historical average, recent average, last-3d rows, and recent-vs-historical %. Use this to assess whether the weakness is isolated to one country or part of a broader multi-country same-source pattern.
- inv_trace_target_last_seen: Last seen timestamp plus recent window counts for the target group. Use this to estimate when the interruption started.
- inv_trace_recent_target_sample: Optional recent sample rows for the target group. Use this only if the trend and peer evidence are not enough.

Inputs must include exactly:
- country_code
- source
""".strip()


@dataclass
class AppConfig:
    database: str
    athena_output: str
    workgroup: str
    model_id: str
    report_file: str
    log_file: str
    region_name: Optional[str]
    max_steps: int
    max_candidates: Optional[int]
    athena_timeout_seconds: int = 180
    athena_poll_seconds: float = 1.0
    max_model_tokens: int = 2500
    temperature: float = 0.0


@dataclass
class SourceSessionState:
    source_key: str
    broader_multi_country_confirmed: bool = False
    broader_multi_country_evidence: List[str] = field(default_factory=list)
    broader_multi_country_established_by: Optional[str] = None
    country_wide_ruled_out: bool = False
    country_wide_evidence: List[str] = field(default_factory=list)
    country_wide_established_by: Optional[str] = None


@dataclass
class CountrySessionState:
    country_code: str
    country_peer_analysis_done: bool = False
    country_peer_evidence: List[str] = field(default_factory=list)
    country_peer_established_by: Optional[str] = None


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def clean_string(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def safe_decimal(value: Any, default: Optional[Decimal] = None) -> Optional[Decimal]:
    if value is None:
        return default
    if isinstance(value, Decimal):
        return value
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return Decimal(value)
    if isinstance(value, float):
        return Decimal(str(value))

    text = str(value).strip()
    if not text:
        return default

    lowered = text.lower()
    if lowered in {"none", "null", "nan", "n/a"}:
        return default

    normalized = text.replace(",", "")
    if normalized.endswith("%"):
        normalized = normalized[:-1].strip()
    if not normalized:
        return default

    try:
        return Decimal(normalized)
    except InvalidOperation:
        return default


def safe_float(value: Any, default: Optional[float] = None) -> Optional[float]:
    decimal_value = safe_decimal(value)
    if decimal_value is None:
        return default
    return float(decimal_value)


def safe_int(value: Any, default: Optional[int] = None) -> Optional[int]:
    decimal_value = safe_decimal(value)
    if decimal_value is None:
        return default
    return int(decimal_value)


def format_number(value: Any, decimals: int = 2) -> str:
    if value is None:
        return "none"
    number = safe_float(value)
    if number is None:
        return "none"
    formatted = f"{number:.{decimals}f}"
    if "." in formatted:
        formatted = formatted.rstrip("0").rstrip(".")
    return formatted or "0"


def source_session_key(source: str) -> str:
    source_name = clean_string(source)
    if re.match(r"^[A-Z]{2}_.+", source_name):
        return re.sub(r"^[A-Z]{2}_", "", source_name)
    return source_name


def get_source_session_state(
    session_memory: Dict[str, SourceSessionState],
    source: str,
) -> SourceSessionState:
    key = source_session_key(source)
    if key not in session_memory:
        session_memory[key] = SourceSessionState(source_key=key)
    return session_memory[key]


def get_country_session_state(
    session_memory: Dict[str, CountrySessionState],
    country_code: str,
) -> CountrySessionState:
    key = clean_string(country_code)
    if key not in session_memory:
        session_memory[key] = CountrySessionState(country_code=key)
    return session_memory[key]


def is_near_baseline(recent_vs_hist_pct: Any) -> bool:
    pct = safe_float(recent_vs_hist_pct)
    return pct is not None and pct > MATERIAL_DROP_THRESHOLD_PCT


def is_material_drop(recent_vs_hist_pct: Any) -> bool:
    pct = safe_float(recent_vs_hist_pct)
    return pct is not None and pct <= MATERIAL_DROP_THRESHOLD_PCT


def build_percent_evidence(label: str, recent_vs_hist_pct: Any) -> Optional[str]:
    pct = safe_float(recent_vs_hist_pct)
    if pct is None or not label:
        return None
    return f"{label}: {format_number(pct)}%"


def extract_peer_values(rows: List[Dict[str, Any]], key_field: str) -> List[Tuple[str, float]]:
    peer_values: List[Tuple[str, float]] = []

    for row in rows:
        if clean_string(row.get("comparison_role")).lower() != "peer":
            continue

        key = clean_string(row.get(key_field))
        pct = safe_float(row.get("recent_vs_hist_pct"))
        if key and pct is not None:
            peer_values.append((key, pct))

    return peer_values


def evaluate_country_peer_results(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    peer_values = extract_peer_values(rows, "source")

    near_baseline_count = sum(1 for _, pct in peer_values if pct > MATERIAL_DROP_THRESHOLD_PCT)
    material_drop_count = sum(1 for _, pct in peer_values if pct <= MATERIAL_DROP_THRESHOLD_PCT)

    return {
        "peer_count": len(peer_values),
        "near_baseline_count": near_baseline_count,
        "material_drop_count": material_drop_count,
        "country_wide_ruled_out": len(peer_values) >= 2 and near_baseline_count > (len(peer_values) / 2.0),
        "country_wide_supported": material_drop_count >= 2,
        "evidence": [
            evidence
            for evidence in (
                build_percent_evidence(source, pct)
                for source, pct in peer_values
            )
            if evidence
        ],
    }


def evaluate_source_family_results(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    peer_values = extract_peer_values(rows, "country_code")

    any_material_drop = any(pct <= MATERIAL_DROP_THRESHOLD_PCT for _, pct in peer_values)
    all_near_baseline = bool(peer_values) and all(
        pct > MATERIAL_DROP_THRESHOLD_PCT for _, pct in peer_values
    )

    return {
        "peer_count": len(peer_values),
        "broader_multi_country_confirmed": any_material_drop,
        "broader_multi_country_ruled_out": all_near_baseline,
        "evidence": [
            evidence
            for evidence in (
                build_percent_evidence(country_code, pct)
                for country_code, pct in peer_values
            )
            if evidence
        ],
    }


def summarize_session_memory_for_prompt(
    country_code: str,
    source: str,
    source_session_state: SourceSessionState,
    country_session_state: CountrySessionState,
) -> str:
    source_key = source_session_state.source_key or source_session_key(source)
    lines = [
        "Session memory for this incident:",
        f"- current country: {country_code}",
        f"- current source: {source}",
        f"- source family key: {source_key}",
    ]

    if source_session_state.broader_multi_country_confirmed:
        evidence = ", ".join(source_session_state.broader_multi_country_evidence[:2]) or "prior peer-country evidence recorded"
        established_by = source_session_state.broader_multi_country_established_by or "an earlier group"
        lines.append(
            "- broader multi-country same-source weakness already established earlier "
            f"by {established_by} using {SOURCE_FAMILY_QUERY}; skip {SOURCE_FAMILY_QUERY} "
            f"and record \"{SOURCE_FAMILY_QUERY}: session: already established for {source}\" in skipped_queries"
        )
        lines.append(f"- prior source-family evidence: {evidence}")
    else:
        lines.append("- no prior session finding has established broader multi-country same-source weakness")

    if country_session_state.country_peer_analysis_done:
        evidence = ", ".join(country_session_state.country_peer_evidence[:2]) or "prior same-country peer evidence recorded"
        established_by = country_session_state.country_peer_established_by or "an earlier group"
        lines.append(
            "- country-level peer analysis already ran earlier "
            f"for {country_code} by {established_by} using {COUNTRY_PEERS_QUERY}; skip {COUNTRY_PEERS_QUERY} "
            f"and record \"{COUNTRY_PEERS_QUERY}: session: already established for {country_code}\" in skipped_queries"
        )
        lines.append(f"- prior country-peer evidence: {evidence}")
    else:
        lines.append("- no prior session finding has established country-level peer analysis for this country")

    return "\n".join(lines)


def build_session_skip_label(query_name: str, established_for: str) -> str:
    return f"{query_name}: session: already established for {established_for}"


def ensure_parent_dir(path: str) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)


def initialize_output_files(config: AppConfig) -> None:
    ensure_parent_dir(config.report_file)
    ensure_parent_dir(config.log_file)
    with open(config.report_file, "w", encoding="utf-8") as report_handle:
        report_handle.write("")
    with open(config.log_file, "w", encoding="utf-8") as log_handle:
        json.dump({}, log_handle)


def build_clients(config: AppConfig):
    session = boto3.session.Session(region_name=config.region_name)
    athena_client = session.client("athena")
    bedrock_client = session.client("bedrock-runtime")
    return athena_client, bedrock_client


def get_named_query_sql(athena_client, query_id: str) -> Dict[str, Any]:
    named_query = athena_client.get_named_query(NamedQueryId=query_id)["NamedQuery"]
    return {
        "name": named_query["Name"],
        "sql": named_query["QueryString"],
        "database": named_query.get("Database"),
    }


def resolve_query_ids(athena_client, config: AppConfig) -> Dict[str, Dict[str, Any]]:
    named_query_ids: List[str] = []
    paginator = athena_client.get_paginator("list_named_queries")

    for page in paginator.paginate(WorkGroup=config.workgroup):
        named_query_ids.extend(page.get("NamedQueryIds", []))

    resolved: Dict[str, Dict[str, Any]] = {}

    for query_id in named_query_ids:
        query_meta = get_named_query_sql(athena_client, query_id)
        name = query_meta["name"]
        if name in REQUIRED_NAMED_QUERIES:
            resolved[name] = {
                "id": query_id,
                "sql": query_meta["sql"],
                "database": query_meta["database"] or config.database,
            }

    missing = [name for name in REQUIRED_NAMED_QUERIES if name not in resolved]
    if missing:
        raise RuntimeError(f"Missing named queries in workgroup '{config.workgroup}': {', '.join(missing)}")

    return resolved


def execute_athena_sql(
    athena_client,
    sql: str,
    config: AppConfig,
    database: Optional[str] = None,
) -> List[Dict[str, Any]]:
    start_kwargs: Dict[str, Any] = {
        "QueryString": sql,
        "ResultConfiguration": {"OutputLocation": config.athena_output},
        "WorkGroup": config.workgroup,
    }
    effective_database = database or config.database
    if effective_database:
        start_kwargs["QueryExecutionContext"] = {"Database": effective_database}

    response = athena_client.start_query_execution(**start_kwargs)
    execution_id = response["QueryExecutionId"]
    deadline = time.time() + config.athena_timeout_seconds

    while True:
        execution = athena_client.get_query_execution(QueryExecutionId=execution_id)
        status = execution["QueryExecution"]["Status"]["State"]
        if status in {"SUCCEEDED", "FAILED", "CANCELLED"}:
            break
        if time.time() >= deadline:
            raise TimeoutError(f"Athena query timed out after {config.athena_timeout_seconds} seconds")
        time.sleep(config.athena_poll_seconds)

    if status != "SUCCEEDED":
        reason = execution["QueryExecution"]["Status"].get("StateChangeReason", "unknown failure")
        raise RuntimeError(f"Athena query failed with status {status}: {reason}")

    paginator = athena_client.get_paginator("get_query_results")
    headers: Optional[List[str]] = None
    rows_out: List[Dict[str, Any]] = []

    for page_index, page in enumerate(paginator.paginate(QueryExecutionId=execution_id)):
        rows = page["ResultSet"].get("Rows", [])
        if not rows:
            continue

        if page_index == 0:
            headers = [column.get("VarCharValue", "") for column in rows[0]["Data"]]
            rows = rows[1:]

        if not headers:
            continue

        for row in rows:
            values = [cell.get("VarCharValue") for cell in row.get("Data", [])]
            if len(values) < len(headers):
                values.extend([None] * (len(headers) - len(values)))
            rows_out.append(dict(zip(headers, values)))

    return rows_out


def escape_sql_literal(value: str) -> str:
    return value.replace("'", "''")


def render_named_query_sql(query_sql: str, params: Optional[Dict[str, Any]] = None) -> str:
    sql = query_sql
    params = params or {}

    for key in ("country_code", "source"):
        if f"{{{{{key}}}}}" in sql:
            value = clean_string(params.get(key))
            if not value:
                raise ValueError(f"Missing required param: {key}")
            sql = sql.replace(f"{{{{{key}}}}}", escape_sql_literal(value))

    if "{{" in sql or "}}" in sql:
        raise ValueError("Unresolved named-query placeholders remain after parameter substitution")

    return sql


def run_named_query(
    query_name: str,
    params: Dict[str, Any],
    query_cache: Dict[str, Dict[str, Any]],
    athena_client,
    config: AppConfig,
) -> Dict[str, Any]:
    if query_name not in ALLOWED_TOOL_QUERY_NAMES:
        return {
            "error": f"Invalid query_name '{query_name}'. Allowed values: {', '.join(ALLOWED_TOOL_QUERY_NAMES)}",
        }

    if query_name not in query_cache:
        return {"error": f"Named query '{query_name}' is not resolved in this environment"}

    country_code = clean_string(params.get("country_code"))
    source = clean_string(params.get("source"))
    if not country_code or not source:
        return {"error": "Params must include non-empty 'country_code' and 'source' values"}

    query_meta = query_cache[query_name]

    try:
        sql = render_named_query_sql(query_meta["sql"], {"country_code": country_code, "source": source})
        results = execute_athena_sql(
            athena_client=athena_client,
            sql=sql,
            config=config,
            database=query_meta.get("database"),
        )
        return {"query_name": query_name, "results": results}
    except Exception as exc:
        return {"query_name": query_name, "error": str(exc)}


def execute_tool(
    tool_name: str,
    tool_input: Dict[str, Any],
    query_cache: Dict[str, Dict[str, Any]],
    athena_client,
    config: AppConfig,
) -> Dict[str, Any]:
    if tool_name != "run_named_query":
        return {"error": f"Unsupported tool: {tool_name}"}

    return run_named_query(
        query_name=clean_string(tool_input.get("query_name")),
        params=tool_input.get("params") or {},
        query_cache=query_cache,
        athena_client=athena_client,
        config=config,
    )


def candidate_sort_key(incident: Dict[str, Any]) -> Tuple[Any, Any, Any, Any]:
    last_3d_total = incident.get("last_3d_total_rows")
    recent_vs_hist_pct = incident.get("recent_vs_hist_pct")
    hist_avg = incident.get("hist_28d_avg_daily_rows")
    return (
        0 if last_3d_total == 0 else 1,
        recent_vs_hist_pct if recent_vs_hist_pct is not None else float("inf"),
        -(hist_avg or 0.0),
        incident.get("group", ""),
    )


def fetch_candidate_incidents(
    athena_client,
    query_cache: Dict[str, Dict[str, Any]],
    config: AppConfig,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    prep_query = query_cache[PREP_QUERY_NAME]
    prep_sql = render_named_query_sql(prep_query["sql"])
    rows = execute_athena_sql(
        athena_client=athena_client,
        sql=prep_sql,
        config=config,
        database=prep_query.get("database"),
    )

    candidates: List[Dict[str, Any]] = []
    malformed_rows = 0
    skipped_below_baseline = 0
    skipped_not_suspicious = 0

    for row_index, row in enumerate(rows, start=1):
        country_code = clean_string(row.get("country_code"))
        source = clean_string(row.get("source"))
        hist_avg = safe_float(row.get("hist_28d_avg_daily_rows"))
        recent_avg = safe_float(row.get("last_7d_avg_daily_rows"), default=0.0)
        hist_total = safe_int(row.get("hist_28d_total_rows"))
        last_7d_total = safe_int(row.get("last_7d_total_rows"))
        last_3d_total = safe_int(row.get("last_3d_total_rows"), default=0)
        recent_vs_hist_pct = safe_float(row.get("recent_vs_hist_pct"))

        if not country_code or not source or hist_avg is None or last_3d_total is None:
            malformed_rows += 1
            continue

        if hist_avg < 3:
            skipped_below_baseline += 1
            continue

        is_candidate = last_3d_total == 0 or recent_avg <= 0.3 * hist_avg
        if not is_candidate:
            skipped_not_suspicious += 1
            continue

        if recent_vs_hist_pct is None and hist_avg > 0:
            recent_vs_hist_pct = round((recent_avg / hist_avg) * 100.0, 2)

        candidates.append(
            {
                "row_index": row_index,
                "incident_type": INCIDENT_TYPE,
                "group": f"{country_code} | {source}",
                "country_code": country_code,
                "source": source,
                "hist_28d_avg_daily_rows": hist_avg,
                "last_7d_avg_daily_rows": recent_avg,
                "hist_28d_total_rows": hist_total,
                "last_7d_total_rows": last_7d_total,
                "last_3d_total_rows": last_3d_total,
                "recent_vs_hist_pct": recent_vs_hist_pct,
            }
        )

    candidates.sort(key=candidate_sort_key)

    total_candidates = len(candidates)
    investigated_candidates = candidates
    if config.max_candidates is not None:
        investigated_candidates = candidates[: config.max_candidates]

    summary = {
        "query_name": PREP_QUERY_NAME,
        "rows_returned": len(rows),
        "malformed_rows_skipped": malformed_rows,
        "skipped_below_hist_threshold": skipped_below_baseline,
        "skipped_not_suspicious": skipped_not_suspicious,
        "candidate_count": total_candidates,
        "investigated_candidate_count": len(investigated_candidates),
        "candidates": investigated_candidates,
    }

    return investigated_candidates, summary


def build_tool_config() -> Dict[str, Any]:
    return {
        "tools": [
            {
                "toolSpec": {
                    "name": "run_named_query",
                    "description": RUN_NAMED_QUERY_DESCRIPTION,
                    "inputSchema": {
                        "json": {
                            "type": "object",
                            "properties": {
                                "query_name": {
                                    "type": "string",
                                    "enum": ALLOWED_TOOL_QUERY_NAMES,
                                },
                                "params": {
                                    "type": "object",
                                    "properties": {
                                        "country_code": {"type": "string"},
                                        "source": {"type": "string"},
                                    },
                                    "required": ["country_code", "source"],
                                },
                            },
                            "required": ["query_name", "params"],
                        }
                    },
                }
            }
        ]
    }


def build_incident_prompt(
    incident: Dict[str, Any],
    source_session_state: SourceSessionState,
    country_session_state: CountrySessionState,
) -> str:
    return (
        "Investigate this flagged CRM incident.\n\n"
        "Incident candidate:\n"
        f"- incident_type: {incident['incident_type']}\n"
        f"- group: {incident['group']}\n"
        f"- country_code: {incident['country_code']}\n"
        f"- source: {incident['source']}\n"
        f"- historical average daily rows: {format_number(incident['hist_28d_avg_daily_rows'])}\n"
        f"- recent average daily rows (7d): {format_number(incident['last_7d_avg_daily_rows'])}\n"
        f"- rows in last 3 days: {incident['last_3d_total_rows']}\n"
        f"- recent vs historical %: {format_number(incident.get('recent_vs_hist_pct'))}\n\n"
        f"{summarize_session_memory_for_prompt(incident['country_code'], incident['source'], source_session_state, country_session_state)}\n\n"
        "Investigate the likely cause, rule out alternatives where possible, and output the INCIDENT REPORT.\n"
        "Prefer this investigation path unless evidence is already sufficient:\n"
        f"1. {TARGET_TREND_QUERY}\n"
        f"2. {COUNTRY_PEERS_QUERY}\n"
        f"3. {SOURCE_FAMILY_QUERY}\n"
        f"4. {LAST_SEEN_QUERY}\n"
        f"5. {RECENT_SAMPLE_QUERY} only if needed\n"
    )


def call_nova(
    bedrock_client,
    messages: List[Dict[str, Any]],
    system_prompt: str,
    config: AppConfig,
    tool_config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    request: Dict[str, Any] = {
        "modelId": config.model_id,
        "system": [{"text": system_prompt}],
        "messages": messages,
        "inferenceConfig": {
            "maxTokens": config.max_model_tokens,
            "temperature": config.temperature,
        },
    }

    if tool_config is not None:
        request["toolConfig"] = tool_config

    return bedrock_client.converse(**request)


def extract_text_from_message(message: Dict[str, Any]) -> str:
    texts: List[str] = []
    for block in message.get("content", []):
        if "text" in block:
            texts.append(block["text"])
    return "\n".join(texts).strip()


def extract_tool_uses(message: Dict[str, Any]) -> List[Dict[str, Any]]:
    tool_uses: List[Dict[str, Any]] = []
    for block in message.get("content", []):
        if "toolUse" in block:
            tool_uses.append(block["toolUse"])
    return tool_uses


def strip_thinking_blocks(text: str) -> str:
    if not text:
        return ""
    return re.sub(r"<thinking>.*?</thinking>", "", text, flags=re.IGNORECASE | re.DOTALL)


def strip_code_fence(text: str) -> str:
    stripped = text.strip()
    if stripped.startswith("```") and stripped.endswith("```"):
        lines = stripped.splitlines()
        if len(lines) >= 3:
            return "\n".join(lines[1:-1]).strip()
    return stripped


def sanitize_terminal_text(text: str) -> str:
    without_thinking = strip_thinking_blocks(text)
    without_fence = strip_code_fence(without_thinking)
    return without_fence


def summarize_terminal_text(text: str, max_length: int = 240) -> str:
    sanitized = sanitize_terminal_text(text)
    if not sanitized:
        return ""
    if "INCIDENT REPORT" in sanitized:
        return ""
    one_line = re.sub(r"\s+", " ", sanitized).strip()
    if len(one_line) <= max_length:
        return one_line
    return one_line[: max_length - 3].rstrip() + "..."


def extract_incident_report(text: str) -> Optional[Dict[str, Any]]:
    normalized = sanitize_terminal_text(text)
    if not normalized.strip().startswith("{"):
        return None
    try:
        return json.loads(normalized)
    except json.JSONDecodeError:
        return None


def extract_query_results_from_log(
    investigation_log: Dict[str, Any],
    query_name: str,
) -> List[Dict[str, Any]]:
    for step in investigation_log.get("steps", []):
        for tool_call in step.get("tool_calls", []):
            input_payload = tool_call.get("input", {})
            if clean_string(input_payload.get("query_name")) != query_name:
                continue
            output_payload = tool_call.get("output", {})
            if tool_call.get("skipped") or output_payload.get("skipped"):
                continue
            return output_payload.get("results") or []
    return []


def request_required_query(
    messages: List[Dict[str, Any]],
    investigation_log: Dict[str, Any],
    step_log: Dict[str, Any],
    stop_reason: Optional[str],
    query_name: str,
    explanation: str,
) -> None:
    step_log["stop_reason"] = stop_reason
    investigation_log["steps"].append(step_log)
    messages.append(
        {
            "role": "user",
            "content": [
                {
                    "text": (
                        f"You must run {query_name} before giving the verdict {explanation}. "
                        "Then return the final JSON."
                    )
                }
            ],
        }
    )


def extract_target_metrics(
    incident: Dict[str, Any],
    trend_rows: List[Dict[str, Any]],
) -> Dict[str, Any]:
    metric_source = trend_rows[0] if trend_rows else {}
    hist_avg = safe_float(metric_source.get("hist_28d_avg_daily_rows"))
    recent_avg = safe_float(metric_source.get("last_7d_avg_daily_rows"))
    last_3d_rows = safe_int(metric_source.get("last_3d_total_rows"))
    recent_vs_hist_pct = safe_float(metric_source.get("recent_vs_hist_pct"))

    if hist_avg is None:
        hist_avg = safe_float(incident.get("hist_28d_avg_daily_rows"))
    if recent_avg is None:
        recent_avg = safe_float(incident.get("last_7d_avg_daily_rows"))
    if last_3d_rows is None:
        last_3d_rows = safe_int(incident.get("last_3d_total_rows"))
    if recent_vs_hist_pct is None:
        recent_vs_hist_pct = safe_float(incident.get("recent_vs_hist_pct"))

    return {
        "hist_avg": hist_avg,
        "recent_avg": recent_avg,
        "last_3d_rows": last_3d_rows,
        "recent_vs_hist_pct": recent_vs_hist_pct,
    }


def extract_last_seen_timestamp(last_seen_rows: List[Dict[str, Any]]) -> Optional[str]:
    if not last_seen_rows:
        return None
    raw_value = clean_string(last_seen_rows[0].get("last_seen_row_timestamp"))
    return raw_value or None


def infer_skipped_queries(
    incident: Dict[str, Any],
    report_dict: Dict[str, Any],
    executed_queries: List[str],
    source_session_state: SourceSessionState,
    country_session_state: CountrySessionState,
) -> List[str]:
    skipped: List[str] = []
    executed_set = set(executed_queries)
    verdict = clean_string(report_dict.get("verdict")).lower()

    if SOURCE_FAMILY_QUERY not in executed_set and source_session_state.broader_multi_country_confirmed:
        skipped.append(build_session_skip_label(SOURCE_FAMILY_QUERY, incident["source"]))
    if COUNTRY_PEERS_QUERY not in executed_set and country_session_state.country_peer_analysis_done:
        skipped.append(build_session_skip_label(COUNTRY_PEERS_QUERY, incident["country_code"]))

    ruled_out_reason = "not needed: target trend did not confirm a material sustained drop"
    if (
        SOURCE_FAMILY_QUERY not in executed_set
        and not any(item.startswith(f"{SOURCE_FAMILY_QUERY}:") for item in skipped)
    ):
        if verdict == "ruled_out":
            skipped.append(f"{SOURCE_FAMILY_QUERY}: {ruled_out_reason}")
        else:
            skipped.append(f"{SOURCE_FAMILY_QUERY}: {DEFAULT_SKIP_REASON}")

    if RECENT_SAMPLE_QUERY not in executed_set:
        skipped.append(f"{RECENT_SAMPLE_QUERY}: {DEFAULT_SKIP_REASON}")

    deduped: List[str] = []
    seen = set()
    for item in skipped:
        if item in seen:
            continue
        seen.add(item)
        deduped.append(item)
    return deduped


def normalize_report_dict(
    report_dict: Dict[str, Any],
    incident: Dict[str, Any],
    investigation_log: Dict[str, Any],
    source_session_state: SourceSessionState,
    country_session_state: CountrySessionState,
) -> Dict[str, Any]:
    trend_rows = extract_query_results_from_log(investigation_log, TARGET_TREND_QUERY)
    last_seen_rows = extract_query_results_from_log(investigation_log, LAST_SEEN_QUERY)
    metrics = extract_target_metrics(incident, trend_rows)

    executed_queries: List[str] = []
    for step in investigation_log.get("steps", []):
        for tool_call in step.get("tool_calls", []):
            input_payload = tool_call.get("input", {})
            query_name = clean_string(input_payload.get("query_name"))
            if not query_name:
                continue
            if tool_call.get("skipped") or tool_call.get("output", {}).get("skipped"):
                continue
            executed_queries.append(query_name)

    normalized = dict(report_dict)
    normalized["group"] = incident["group"]
    normalized["country_code"] = incident["country_code"]
    normalized["source"] = incident["source"]
    normalized["hist_avg"] = metrics["hist_avg"]
    normalized["recent_avg"] = metrics["recent_avg"]
    normalized["last_3d_rows"] = metrics["last_3d_rows"]
    normalized["recent_vs_hist_pct"] = metrics["recent_vs_hist_pct"]
    normalized["last_seen"] = extract_last_seen_timestamp(last_seen_rows)
    normalized["skipped_queries"] = infer_skipped_queries(
        incident=incident,
        report_dict=normalized,
        executed_queries=executed_queries,
        source_session_state=source_session_state,
        country_session_state=country_session_state,
    )

    if not clean_string(normalized.get("summary")):
        normalized["summary"] = "Investigation completed with limited model narrative."
    if not clean_string(normalized.get("most_likely_explanation")):
        normalized["most_likely_explanation"] = "The available query evidence did not support a more specific explanation."
    if not clean_string(normalized.get("impact")):
        hist_avg = format_number(normalized.get("hist_avg"))
        recent_avg = format_number(normalized.get("recent_avg"))
        normalized["impact"] = (
            f"Recent average is {recent_avg} rows/day versus {hist_avg} historically for {incident['group']}."
        )

    return normalized


def update_session_memory_from_investigation(
    investigation_log: Dict[str, Any],
    source_session_state: SourceSessionState,
    country_session_state: CountrySessionState,
    group: str,
) -> None:
    country_peer_rows = extract_query_results_from_log(investigation_log, COUNTRY_PEERS_QUERY)
    if country_peer_rows:
        country_eval = evaluate_country_peer_results(country_peer_rows)
        country_session_state.country_peer_analysis_done = True
        country_session_state.country_peer_established_by = group
        country_session_state.country_peer_evidence = country_eval["evidence"][:2]

    source_family_rows = extract_query_results_from_log(investigation_log, SOURCE_FAMILY_QUERY)
    if source_family_rows:
        family_eval = evaluate_source_family_results(source_family_rows)
        if family_eval["broader_multi_country_confirmed"]:
            source_session_state.broader_multi_country_confirmed = True
            source_session_state.broader_multi_country_established_by = group
            source_session_state.broader_multi_country_evidence = family_eval["evidence"][:2]


def build_fallback_error_note(incident: Dict[str, Any], reason: str) -> Dict[str, Any]:
    return {
        "group": incident['group'],
        "country_code": incident['country_code'],
        "source": incident['source'],
        "verdict": "error",
        "pattern": "Error",
        "hist_avg": incident['hist_28d_avg_daily_rows'],
        "recent_avg": incident['last_7d_avg_daily_rows'],
        "last_3d_rows": incident['last_3d_total_rows'],
        "recent_vs_hist_pct": incident.get('recent_vs_hist_pct'),
        "last_seen": None,
        "skipped_queries": [],
        "summary": "INVESTIGATION ERROR",
        "most_likely_explanation": reason,
        "impact": "Investigation failed before completion."
    }


def save_report(report_payload: Dict[str, Any], report_file: str) -> None:
    ensure_parent_dir(report_file)
    with open(report_file, "a", encoding="utf-8") as handle:
        json.dump(report_payload, handle, indent=2, ensure_ascii=False)
        handle.write("\n\n")
        handle.write("-" * 60)
        handle.write("\n\n")


def save_log(log_payload: Dict[str, Any], log_file: str) -> None:
    ensure_parent_dir(log_file)
    with open(log_file, "w", encoding="utf-8") as handle:
        json.dump(log_payload, handle, indent=2, ensure_ascii=False)


def run_investigation(
    incident: Dict[str, Any],
    athena_client,
    bedrock_client,
    query_cache: Dict[str, Dict[str, Any]],
    config: AppConfig,
    tool_config: Dict[str, Any],
    source_session_memory: Dict[str, SourceSessionState],
    country_session_memory: Dict[str, CountrySessionState],
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    print("-" * 60)
    print(f"Investigating: {incident['group']}")
    print(f"Historical avg: {format_number(incident['hist_28d_avg_daily_rows'])}")
    print(f"Recent avg: {format_number(incident['last_7d_avg_daily_rows'])}")
    print(f"Last 3d rows: {incident['last_3d_total_rows']}")
    print("-" * 60)

    source_session_state = get_source_session_state(source_session_memory, incident["source"])
    country_session_state = get_country_session_state(country_session_memory, incident["country_code"])
    messages = [
        {
            "role": "user",
            "content": [
                {
                    "text": build_incident_prompt(
                        incident,
                        source_session_state,
                        country_session_state,
                    )
                }
            ],
        }
    ]
    investigation_log: Dict[str, Any] = {
        "candidate": incident,
        "started_at": utc_now_iso(),
        "status": "in_progress",
        "session_memory_before": {
            "source": asdict(source_session_state),
            "country": asdict(country_session_state),
        },
        "steps": [],
        "final_report": None,
    }

    for step_number in range(1, config.max_steps + 1):
        print(f"\n--- [Step {step_number}] Investigation: {incident['group']} ---")

        step_log: Dict[str, Any] = {
            "step": step_number,
            "assistant_text": None,
            "tool_calls": [],
        }

        try:
            response = call_nova(
                bedrock_client=bedrock_client,
                messages=messages,
                system_prompt=NOVA_SYSTEM_PROMPT,
                config=config,
                tool_config=tool_config,
            )
        except (BotoCoreError, ClientError, Exception) as exc:
            reason = f"Nova call failed: {exc}"
            report_dict = build_fallback_error_note(incident, reason)
            investigation_log["status"] = "error"
            investigation_log["finished_at"] = utc_now_iso()
            investigation_log["error"] = reason
            investigation_log["final_report"] = report_dict
            investigation_log["session_memory_after"] = {
                "source": asdict(source_session_state),
                "country": asdict(country_session_state),
            }
            save_report(report_dict, config.report_file)
            print(json.dumps(report_dict, indent=2))
            return report_dict, investigation_log

        assistant_message = response["output"]["message"]
        stop_reason = response.get("stopReason")
        messages.append(assistant_message)

        assistant_text = extract_text_from_message(assistant_message)
        if assistant_text:
            step_log["assistant_text"] = assistant_text
            step_log["assistant_text_sanitized"] = sanitize_terminal_text(assistant_text)
        tool_uses = extract_tool_uses(assistant_message)
        if tool_uses:
            assistant_summary = summarize_terminal_text(assistant_text)
            if assistant_summary:
                print(f"[Nova] {assistant_summary}")
            tool_result_content: List[Dict[str, Any]] = []

            for tool_use in tool_uses:
                tool_name = tool_use["name"]
                tool_input = tool_use.get("input", {})
                serialized_input = json.dumps(tool_input, sort_keys=True)
                print(f"[Tool] {tool_name}: {serialized_input}")

                query_name = clean_string(tool_input.get("query_name"))
                skipped = False
                if (
                    query_name == COUNTRY_PEERS_QUERY
                    and country_session_state.country_peer_analysis_done
                ):
                    skipped = True
                    tool_output = {
                        "query_name": query_name,
                        "skipped": True,
                        "reason": f"session: already established for {incident['country_code']}",
                    }
                elif (
                    query_name == SOURCE_FAMILY_QUERY
                    and source_session_state.broader_multi_country_confirmed
                ):
                    skipped = True
                    tool_output = {
                        "query_name": query_name,
                        "skipped": True,
                        "reason": f"session: already established for {incident['source']}",
                    }
                else:
                    tool_output = execute_tool(
                        tool_name=tool_name,
                        tool_input=tool_input,
                        query_cache=query_cache,
                        athena_client=athena_client,
                        config=config,
                    )
                serialized_output = json.dumps(tool_output, default=str, ensure_ascii=False)
                print(f"[Result] {len(serialized_output)} chars")

                step_log["tool_calls"].append(
                    {
                        "tool_name": tool_name,
                        "tool_use_id": tool_use["toolUseId"],
                        "input": tool_input,
                        "output": tool_output,
                        "skipped": skipped,
                    }
                )

                tool_result_content.append(
                    {
                        "toolResult": {
                            "toolUseId": tool_use["toolUseId"],
                            "content": [{"json": tool_output}],
                        }
                    }
                )

            investigation_log["steps"].append(step_log)
            messages.append({"role": "user", "content": tool_result_content})
            continue

        report_dict = extract_incident_report(assistant_text)
        if report_dict:
            required_query_checks = [
                (
                    TARGET_TREND_QUERY,
                    not extract_query_results_from_log(investigation_log, TARGET_TREND_QUERY),
                    "so the drop is verified against the recent daily trend",
                ),
                (
                    COUNTRY_PEERS_QUERY,
                    (
                        not extract_query_results_from_log(investigation_log, COUNTRY_PEERS_QUERY)
                        and not country_session_state.country_peer_analysis_done
                    ),
                    "because it is country-level analysis for the current flagged country",
                ),
                (
                    LAST_SEEN_QUERY,
                    not extract_query_results_from_log(investigation_log, LAST_SEEN_QUERY),
                    "so the final analysis includes when the interruption started",
                ),
            ]

            missing_required_query = next(
                (
                    (query_name, explanation)
                    for query_name, is_missing, explanation in required_query_checks
                    if is_missing
                ),
                None,
            )
            if missing_required_query is not None:
                query_name, explanation = missing_required_query
                request_required_query(
                    messages=messages,
                    investigation_log=investigation_log,
                    step_log=step_log,
                    stop_reason=stop_reason,
                    query_name=query_name,
                    explanation=explanation,
                )
                continue

            normalized_report = normalize_report_dict(
                report_dict=report_dict,
                incident=incident,
                investigation_log=investigation_log,
                source_session_state=source_session_state,
                country_session_state=country_session_state,
            )
            investigation_log["status"] = "completed"
            investigation_log["finished_at"] = utc_now_iso()
            investigation_log["final_report"] = normalized_report
            step_log["stop_reason"] = stop_reason
            investigation_log["steps"].append(step_log)
            update_session_memory_from_investigation(
                investigation_log,
                source_session_state,
                country_session_state,
                incident["group"],
            )
            investigation_log["session_memory_after"] = {
                "source": asdict(source_session_state),
                "country": asdict(country_session_state),
            }
            save_report(normalized_report, config.report_file)
            print(json.dumps(normalized_report, indent=2))
            return normalized_report, investigation_log

        assistant_summary = summarize_terminal_text(assistant_text)
        if assistant_summary:
            print(f"[Nova] {assistant_summary}")

        step_log["stop_reason"] = stop_reason
        investigation_log["steps"].append(step_log)
        messages.append(
            {
                "role": "user",
                "content": [
                    {
                        "text": (
                            "Return the final JSON output now using the exact required format. "
                            "Do not add commentary before or after the JSON block."
                        )
                    }
                ],
            }
        )

    reason = f"Nova did not return a valid JSON object within {config.max_steps} steps."
    report_dict = build_fallback_error_note(incident, reason)
    investigation_log["status"] = "max_steps_exceeded"
    investigation_log["finished_at"] = utc_now_iso()
    investigation_log["error"] = reason
    investigation_log["final_report"] = report_dict
    investigation_log["session_memory_after"] = {
        "source": asdict(source_session_state),
        "country": asdict(country_session_state),
    }
    save_report(report_dict, config.report_file)
    print(json.dumps(report_dict, indent=2))
    return report_dict, investigation_log


def parse_args() -> AppConfig:
    parser = argparse.ArgumentParser(
        description="Investigate flagged CRM source volume drop incidents with Athena and Bedrock Nova."
    )
    parser.add_argument("--database", default=DEFAULT_DATABASE, help="Default Athena database for query execution.")
    parser.add_argument(
        "--athena-output",
        default=DEFAULT_ATHENA_OUTPUT,
        help="S3 path for Athena query results.",
    )
    parser.add_argument("--workgroup", default=DEFAULT_WORKGROUP, help="Athena workgroup containing named queries.")
    parser.add_argument("--model-id", default=DEFAULT_MODEL_ID, help="Bedrock model or inference profile ID.")
    parser.add_argument("--region", default=None, help="AWS region for Athena and Bedrock clients.")
    parser.add_argument(
        "--report-file",
        default=DEFAULT_REPORT_FILE,
        help="Path to the text file that stores final incident reports.",
    )
    parser.add_argument(
        "--log-file",
        default=DEFAULT_LOG_FILE,
        help="Path to the JSON file that stores the investigation log.",
    )
    parser.add_argument(
        "--max-steps",
        type=int,
        default=8,
        help="Maximum Bedrock tool-use loop steps per incident.",
    )
    parser.add_argument(
        "--max-candidates",
        type=int,
        default=None,
        help="Optional cap on how many candidate incidents to investigate.",
    )

    args = parser.parse_args()

    return AppConfig(
        database=args.database,
        athena_output=args.athena_output,
        workgroup=args.workgroup,
        model_id=args.model_id,
        report_file=args.report_file,
        log_file=args.log_file,
        region_name=args.region,
        max_steps=args.max_steps,
        max_candidates=args.max_candidates,
    )


def main() -> int:
    config = parse_args()
    initialize_output_files(config)

    log_payload: Dict[str, Any] = {
        "generated_at": utc_now_iso(),
        "app": APP_TITLE,
        "incident_type": INCIDENT_TYPE,
        "config": asdict(config),
        "candidate_detection": {},
        "investigations": [],
    }
    save_log(log_payload, config.log_file)

    print("=" * 60)
    print(APP_TITLE)
    print("=" * 60)

    try:
        athena_client, bedrock_client = build_clients(config)
    except (BotoCoreError, ClientError, Exception) as exc:
        print(f"[Init] Failed to create AWS clients: {exc}")
        log_payload["fatal_error"] = f"Failed to create AWS clients: {exc}"
        save_log(log_payload, config.log_file)
        return 1

    print("[Init] Resolving named queries...")
    try:
        query_cache = resolve_query_ids(athena_client, config)
    except Exception as exc:
        print(f"[Init] Failed to resolve named queries: {exc}")
        log_payload["fatal_error"] = f"Failed to resolve named queries: {exc}"
        save_log(log_payload, config.log_file)
        return 1

    log_payload["resolved_named_queries"] = sorted(query_cache.keys())
    save_log(log_payload, config.log_file)
    print(f"[Init] Resolved named queries: {len(query_cache)}")

    print("[Init] Running candidate detection query...")
    try:
        candidates, candidate_summary = fetch_candidate_incidents(
            athena_client=athena_client,
            query_cache=query_cache,
            config=config,
        )
    except Exception as exc:
        print(f"[Init] Candidate detection failed: {exc}")
        log_payload["fatal_error"] = f"Candidate detection failed: {exc}"
        save_log(log_payload, config.log_file)
        return 1

    log_payload["candidate_detection"] = candidate_summary
    save_log(log_payload, config.log_file)

    print(f"[Init] Candidate incidents found: {len(candidates)}")

    if config.max_candidates is not None and candidate_summary["candidate_count"] > len(candidates):
        print(
            f"[Init] Limiting investigation to {len(candidates)} candidates "
            f"because --max-candidates={config.max_candidates}."
        )

    if not candidates:
        print("[Done] No candidate incidents met the deterministic threshold.")
        print(f"[Done] Reports file: {os.path.abspath(config.report_file)}")
        print(f"[Done] Log file: {os.path.abspath(config.log_file)}")
        return 0

    tool_config = build_tool_config()
    source_session_memory: Dict[str, SourceSessionState] = {}
    country_session_memory: Dict[str, CountrySessionState] = {}

    for incident in candidates:
        report_dict, investigation_log = run_investigation(
            incident=incident,
            athena_client=athena_client,
            bedrock_client=bedrock_client,
            query_cache=query_cache,
            config=config,
            tool_config=tool_config,
            source_session_memory=source_session_memory,
            country_session_memory=country_session_memory,
        )
        investigation_log["saved_report_excerpt"] = report_dict.get('summary') if report_dict else None
        log_payload["investigations"].append(investigation_log)
        save_log(log_payload, config.log_file)

    print("\n" + "=" * 60)
    print("INVESTIGATION COMPLETE")
    print("=" * 60)
    print(f"Investigations run: {len(log_payload['investigations'])}")
    print(f"Report file: {os.path.abspath(config.report_file)}")
    print(f"Log file: {os.path.abspath(config.log_file)}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
