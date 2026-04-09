from typing import Any

def first_cvss_score(metrics):
    if not metrics:
        return None
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        items = metrics.get(key)
        if items:
            score = items[0].get("cvssData", {}).get("baseScore")
            if score is not None:
                return float(score)
    return None

def extract_cpe_targets(configurations) -> list[dict[str, Any]]:
    targets = []
    def walk_node(node):
        for match in node.get("cpeMatch", []) or []:
            criteria = match.get("criteria") or match.get("cpe23Uri") or ""
            parts = criteria.split(":")
            vendor = parts[3].lower() if len(parts) > 3 else None
            product = parts[4].lower() if len(parts) > 4 else None
            version = parts[5] if len(parts) > 5 else None
            targets.append({
                "criteria": criteria,
                "vendor": vendor,
                "product": product,
                "version": version,
                "vulnerable": bool(match.get("vulnerable", False)),
                "versionStartIncluding": match.get("versionStartIncluding"),
                "versionStartExcluding": match.get("versionStartExcluding"),
                "versionEndIncluding": match.get("versionEndIncluding"),
                "versionEndExcluding": match.get("versionEndExcluding"),
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
    return targets

def normalize_vulnerability(vuln):
    cve = vuln["cve"]
    descriptions = cve.get("descriptions", []) or []
    desc_en = next((d.get("value") for d in descriptions if d.get("lang") == "en"), None)
    configurations = cve.get("configurations", []) or []
    cpe_targets = extract_cpe_targets(configurations)
    cpe_products = sorted({t["product"] for t in cpe_targets if t.get("product")})
    cpe_vendors = sorted({t["vendor"] for t in cpe_targets if t.get("vendor")})
    return {
        "id": cve["id"],
        "sourceIdentifier": cve.get("sourceIdentifier"),
        "published": cve.get("published"),
        "lastModified": cve.get("lastModified"),
        "vulnStatus": cve.get("vulnStatus"),
        "metrics": cve.get("metrics", {}),
        "baseScore": first_cvss_score(cve.get("metrics")),
        "configurations": configurations,
        "cpeTargets": cpe_targets,
        "cpeProducts": cpe_products,
        "cpeVendors": cpe_vendors,
        "descriptions": descriptions,
        "description_en": desc_en,
        "references": cve.get("references", []),
        "weaknesses": cve.get("weaknesses", []),
        "nvdUrl": f"https://nvd.nist.gov/vuln/detail/{cve['id']}",
    }
