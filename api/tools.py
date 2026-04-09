import json
import logging
import re
from typing import Any

import requests
from opensearchpy import OpenSearch
from packaging.version import InvalidVersion, Version
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from config import settings

logger = logging.getLogger("versionguard.tools")
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NUMERIC_RE = re.compile(r"(\d+)")

PACKAGE_ALIASES = {
    "openssl": {"openssl"},
    "express": {"express", "expressjs"},
    "log4j": {"log4j", "logging_log4j", "apache"},
    "django": {"django", "djangoproject"},
    "flask": {"flask", "palletsprojects"},
}

class SoftwareNotFoundError(Exception):
    pass

class InvalidSoftwareVersionError(Exception):
    pass

class LooseVersion:
    def __init__(self, parts: tuple[int, ...]) -> None:
        self.parts = parts
    def _pad(self, other: "LooseVersion"):
        n = max(len(self.parts), len(other.parts))
        return self.parts + (0,) * (n - len(self.parts)), other.parts + (0,) * (n - len(other.parts))
    def __lt__(self, other: "LooseVersion") -> bool:
        a, b = self._pad(other)
        return a < b
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, LooseVersion):
            return False
        a, b = self._pad(other)
        return a == b

def _normalize_version_text(value: str) -> str:
    value = value.strip().lstrip("vV").replace("_", ".").replace("-", ".")
    value = re.sub(r"(?i)final|release|ga|sp", "", value)
    value = re.sub(r"\.+", ".", value).strip(".")
    return value

def parse_version(value: str):
    if value is None or not str(value).strip():
        raise InvalidSoftwareVersionError("Version is empty")
    normalized = _normalize_version_text(str(value))
    try:
        return Version(normalized)
    except InvalidVersion:
        numeric = _NUMERIC_RE.findall(normalized)
        if numeric:
            return LooseVersion(tuple(int(x) for x in numeric))
        raise InvalidSoftwareVersionError(f"Unsupported or invalid version format: {value}")

def compare_versions(left: str, right: str) -> int:
    lobj = parse_version(left)
    robj = parse_version(right)
    if lobj < robj:
        return -1
    if lobj > robj:
        return 1
    return 0

def match_version(user_version: str, cpe_ranges: dict[str, Any], strict_mode: bool = True) -> bool:
    exact = cpe_ranges.get("versionExact")
    if exact is not None:
        return compare_versions(user_version, exact) == 0

    vsi = cpe_ranges.get("versionStartIncluding")
    vse = cpe_ranges.get("versionStartExcluding")
    vei = cpe_ranges.get("versionEndIncluding")
    vee = cpe_ranges.get("versionEndExcluding")

    has_bounds = any(v is not None for v in (vsi, vse, vei, vee))
    if not has_bounds:
        return False if strict_mode else True

    if vsi is not None and compare_versions(user_version, vsi) < 0:
        return False
    if vse is not None and compare_versions(user_version, vse) <= 0:
        return False
    if vei is not None and compare_versions(user_version, vei) > 0:
        return False
    if vee is not None and compare_versions(user_version, vee) >= 0:
        return False

    return True

def _criteria_vendor_product_version(criteria: str):
    parts = criteria.split(":")
    vendor = parts[3].lower() if len(parts) > 3 else None
    product = parts[4].lower() if len(parts) > 4 else None
    version = parts[5] if len(parts) > 5 else None
    return vendor, product, version

def _alias_set(package: str) -> set[str]:
    pkg = package.strip().lower()
    aliases = set(PACKAGE_ALIASES.get(pkg, {pkg}))
    aliases.add(pkg)
    return aliases

def _target_matches_package(criteria: str, aliases: set[str]) -> bool:
    vendor, product, _ = _criteria_vendor_product_version(criteria)
    return vendor in aliases or product in aliases

def _extract_score(metrics: dict[str, Any] | None):
    if not metrics:
        return None
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        items = metrics.get(key)
        if items:
            score = items[0].get("cvssData", {}).get("baseScore")
            if score is not None:
                return float(score)
    return None

def _extract_fix_from_description(description: str | None) -> str:
    if not description:
        return "See vendor advisory or latest fixed release."
    for pattern in (r"fixed in ([^\s,;]+)", r"upgrade to ([^\s,;]+)", r"patched in ([^\s,;]+)"):
        m = re.search(pattern, description, flags=re.IGNORECASE)
        if m:
            return m.group(1)
    return "See vendor advisory or latest fixed release."

def _cpe_version_from_criteria(criteria: str):
    _, _, version = _criteria_vendor_product_version(criteria)
    if version not in (None, "*", "-"):
        return version
    return None

def evaluate_cpe_match(cpe_match: dict[str, Any], user_version: str, aliases: set[str]) -> bool:
    if not cpe_match.get("vulnerable", False):
        return False
    criteria = cpe_match.get("criteria") or cpe_match.get("cpe23Uri") or ""
    if not _target_matches_package(criteria, aliases):
        return False
    ranges: dict[str, Any] = {
        "versionStartIncluding": cpe_match.get("versionStartIncluding"),
        "versionStartExcluding": cpe_match.get("versionStartExcluding"),
        "versionEndIncluding": cpe_match.get("versionEndIncluding"),
        "versionEndExcluding": cpe_match.get("versionEndExcluding"),
    }
    if not any(v is not None for v in ranges.values()):
        exact = _cpe_version_from_criteria(criteria)
        if exact is not None:
            ranges["versionExact"] = exact
    return match_version(user_version, ranges, strict_mode=True)

def _evaluate_node(node: dict[str, Any], user_version: str, aliases: set[str]) -> bool:
    operator = str(node.get("operator", "OR")).upper()
    negate = bool(node.get("negate", False))
    results = []
    for item in node.get("cpeMatch", []) or []:
        try:
            results.append(evaluate_cpe_match(item, user_version, aliases))
        except InvalidSoftwareVersionError:
            raise
        except Exception:
            results.append(False)
    for child in node.get("children", []) or []:
        results.append(_evaluate_node(child, user_version, aliases))
    if not results:
        outcome = False
    elif operator == "AND":
        outcome = all(results)
    else:
        outcome = any(results)
    return not outcome if negate else outcome

def is_configuration_vulnerable(configurations: Any, user_version: str, package: str) -> bool:
    aliases = _alias_set(package)
    top_nodes = []
    if isinstance(configurations, dict):
        top_nodes.extend(configurations.get("nodes", []) or [])
    elif isinstance(configurations, list):
        for cfg in configurations:
            if isinstance(cfg, dict):
                top_nodes.extend(cfg.get("nodes", []) or [])
    for node in top_nodes:
        if _evaluate_node(node, user_version, aliases):
            return True
    return False

def _collect_cpe_targets(configurations: Any):
    out = []
    def walk_node(node: dict[str, Any]):
        for item in node.get("cpeMatch", []) or []:
            criteria = item.get("criteria") or item.get("cpe23Uri") or ""
            vendor, product, version = _criteria_vendor_product_version(criteria)
            out.append({
                "criteria": criteria,
                "vendor": vendor,
                "product": product,
                "version": version,
                "vulnerable": bool(item.get("vulnerable", False)),
                "versionStartIncluding": item.get("versionStartIncluding"),
                "versionStartExcluding": item.get("versionStartExcluding"),
                "versionEndIncluding": item.get("versionEndIncluding"),
                "versionEndExcluding": item.get("versionEndExcluding"),
            })
        for child in node.get("children", []) or []:
            walk_node(child)
    if isinstance(configurations, dict):
        for node in configurations.get("nodes", []) or []:
            walk_node(node)
    elif isinstance(configurations, list):
        for cfg in configurations:
            if isinstance(cfg, dict):
                for node in cfg.get("nodes", []) or []:
                    walk_node(node)
    return out

def _candidate_matches_package(item: dict[str, Any], package: str) -> bool:
    aliases = _alias_set(package)
    for target in item.get("cpeTargets", []) or []:
        if target.get("vulnerable") and (target.get("vendor") in aliases or target.get("product") in aliases):
            return True
    return False

def _normalize_live_nvd_vuln(vuln: dict[str, Any]) -> dict[str, Any]:
    cve = vuln["cve"]
    descriptions = cve.get("descriptions", []) or []
    description_en = next((d.get("value") for d in descriptions if d.get("lang") == "en"), None)
    configurations = cve.get("configurations", []) or []
    return {
        "id": cve["id"],
        "severity": _extract_score(cve.get("metrics")),
        "fix": _extract_fix_from_description(description_en),
        "summary": description_en,
        "configurations": configurations,
        "cpeTargets": _collect_cpe_targets(configurations),
        "url": f"https://nvd.nist.gov/vuln/detail/{cve['id']}",
        "source": "nvd-live",
    }

def _nvd_headers():
    return {"apiKey": settings.NVD_API_KEY} if settings.NVD_API_KEY else {}

def _opensearch_client():
    return OpenSearch(settings.OPEN_SEARCH_URL)

def _search_opensearch(package: str):
    aliases = list(_alias_set(package))
    client = _opensearch_client()
    body = {
        "size": 100,
        "query": {
            "bool": {
                "should": [
                    {"terms": {"cpeProducts": aliases}},
                    {"terms": {"cpeVendors": aliases}},
                    {"match_phrase": {"description_en": package}},
                ],
                "minimum_should_match": 1,
            }
        },
    }
    res = client.search(index=settings.OPEN_SEARCH_INDEX, body=body)
    items = []
    for hit in res.get("hits", {}).get("hits", []):
        src = hit.get("_source", {})
        item = {
            "id": src.get("id"),
            "severity": src.get("baseScore"),
            "fix": _extract_fix_from_description(src.get("description_en")),
            "summary": src.get("description_en"),
            "configurations": src.get("configurations", []),
            "cpeTargets": src.get("cpeTargets", []),
            "url": src.get("nvdUrl"),
            "source": "opensearch",
        }
        if _candidate_matches_package(item, package):
            items.append(item)
    return items

@retry(
    retry=retry_if_exception_type((requests.RequestException, RuntimeError)),
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    reraise=True,
)
def _search_nvd_live(package: str) -> list[dict[str, Any]]:
    pkg = package.strip().lower()
    headers = _nvd_headers()

    # Prefer keyword search + strict post-filtering.
    # NVD's cpeName parameter expects valid CPE names, so loose wildcard guesses are unreliable.
    attempts = [
        {"keywordSearch": package, "resultsPerPage": 100},
    ]

    all_items: list[dict[str, Any]] = []
    seen: set[str] = set()

    for params in attempts:
        r = requests.get(NVD_API_URL, headers=headers, params=params, timeout=45)

        if r.status_code in (429, 503):
            raise RuntimeError(f"NVD temporarily unavailable: {r.status_code}")

        # Treat 404/400 here as "no usable search result", not server failure.
        if r.status_code in (400, 404):
            continue

        r.raise_for_status()
        payload = r.json()

        for vuln in payload.get("vulnerabilities", []):
            item = _normalize_live_nvd_vuln(vuln)
            if item["id"] in seen:
                continue
            seen.add(item["id"])

            if _candidate_matches_package(item, package):
                all_items.append(item)

    return all_items


def search_cves(package: str) -> list[dict[str, Any]]:
    package = package.strip()
    if not package:
        raise SoftwareNotFoundError("Software name is empty")

    results: list[dict[str, Any]] = []

    try:
        results = _search_opensearch(package)
    except Exception as exc:
        logger.warning("OpenSearch lookup failed for %s: %s", package, exc)
        results = []

    if not results and settings.ENABLE_NVD_LIVE_FALLBACK:
        try:
            results = _search_nvd_live(package)
        except requests.RequestException as exc:
            logger.warning("NVD lookup failed for %s: %s", package, exc)
            results = []
        except RuntimeError as exc:
            logger.warning("NVD temporary failure for %s: %s", package, exc)
            results = []

    if not results:
        raise SoftwareNotFoundError(
            f"No NVD records were found for software '{package}'. Check the software name or use the official product name."
        )

    return results

def explain_cve(cve_data: dict[str, Any]) -> str:
    prompt = (
        "You are a security assistant. Use only the supplied CVE data. "
        'Return STRICT JSON with one key: "summary".\n\n'
        f"CVE_DATA:\n{json.dumps(cve_data, ensure_ascii=False)}"
    )
    try:
        r = requests.post(
            f"{settings.OLLAMA_BASE_URL}/api/generate",
            json={"model": "llama3.2", "prompt": prompt, "stream": False},
            timeout=90,
        )
        r.raise_for_status()
        raw = r.json().get("response", "").strip()
        try:
            parsed = json.loads(raw)
            return parsed.get("summary", raw)
        except Exception:
            return raw
    except Exception:
        return (
            f"{cve_data.get('id', 'Unknown CVE')} matches the provided version based on NVD configuration data. "
            f"Severity: {cve_data.get('severity')}. Recommended fix: {cve_data.get('fix')}"
        )
