import re
from typing import Any, TypedDict
from langgraph.graph import END, StateGraph
from tools import explain_cve, is_configuration_vulnerable, parse_version, search_cves

PACKAGE_VERSION_RE = re.compile(r"^\s*([A-Za-z0-9._@/\-]+)\s+([A-Za-z0-9._\-+]+)\s*$")

class AgentState(TypedDict, total=False):
    query: str
    package: str
    version: str
    parsed_version: str
    candidates: list[dict[str, Any]]
    matched: list[dict[str, Any]]
    response: dict[str, Any]
    
def parse_query(query: str):
    m = PACKAGE_VERSION_RE.match(query.strip())
    if not m:
        raise ValueError("Query must be in the form '<package> <version>'")
    return m.group(1), m.group(2)

def parse_node(state: AgentState) -> AgentState:
    package, version = parse_query(state["query"])
    parsed = parse_version(version)
    state["package"] = package
    state["version"] = version
    state["parsed_version"] = str(parsed)
    return state

def search_node(state: AgentState) -> AgentState:
    state["candidates"] = search_cves(state["package"])
    return state

def match_node(state: AgentState) -> AgentState:
    package = state["package"]
    version = state["version"]
    matched = []
    for item in state.get("candidates", []):
        if is_configuration_vulnerable(item.get("configurations", []), version, package):
            matched.append(item)
    matched.sort(key=lambda x: (x.get("severity") is None, -(x.get("severity") or 0.0)))
    state["matched"] = matched
    return state

def explain_node(state: AgentState) -> AgentState:
    import re

    def derive_solution(cves: list[dict]) -> str:
        versions = []

        for cve in cves:
            fix = cve.get("fix", "") or ""
            if not fix:
                continue

            matches = re.findall(r"\d+\.\d+(?:\.\d+)?", fix)
            versions.extend(matches)

        if not versions:
            return "Upgrade to the latest stable version from the official vendor."

        def version_key(v: str):
            return tuple(int(x) for x in v.split("."))

        latest = sorted(versions, key=version_key)[-1]
        return f"Upgrade to version {latest} or later."

    matched = state.get("matched", [])
    package = state.get("package")
    version = state.get("version")

    if not matched:
        state["response"] = {
            "vulnerable": False,
            "cves": [],
            "explanation": "The software was found in NVD data, but this exact version is not explicitly marked as vulnerable.",
            "solution": "No action required.",
            "sources": [],
            "package": package,
            "version": version,
            "meta": {
                "candidate_count": len(state.get("candidates", [])),
                "matched_count": 0,
                "parsed_version": state.get("parsed_version"),
            },
        }
        return state

    top = matched[:5]
    cves = []
    sources = []
    explanations = []

    for item in top:
        cves.append(
            {
                "id": item["id"],
                "severity": item.get("severity"),
                "fix": item.get("fix") or "See vendor advisory or latest fixed release.",
                "summary": item.get("summary"),
            }
        )
        if item.get("url"):
            sources.append(item["url"])

    for item in top[:2]:
        explanations.append(explain_cve(item))

    solution = derive_solution(cves)

    state["response"] = {
        "vulnerable": True,
        "cves": cves,
        "explanation": "\n\n".join(explanations),
        "solution": solution,
        "sources": sources,
        "package": package,
        "version": version,
        "meta": {
            "candidate_count": len(state.get("candidates", [])),
            "matched_count": len(matched),
            "parsed_version": state.get("parsed_version"),
        },
    }
    return state

graph = StateGraph(AgentState)
graph.add_node("parse", parse_node)
graph.add_node("search", search_node)
graph.add_node("match", match_node)
graph.add_node("explain", explain_node)
graph.set_entry_point("parse")
graph.add_edge("parse", "search")
graph.add_edge("search", "match")
graph.add_edge("match", "explain")
graph.add_edge("explain", END)
app_graph = graph.compile()
