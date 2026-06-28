"""
Neural Firewall — MCP Threat Intelligence Server
Exposes threat pattern database to ADK agents via MCP protocol.

Run standalone:
    python mcp_server/server.py

Two tools exposed:
    - get_patterns_by_category(category) -> list[dict]
    - search_patterns(query) -> list[dict]
"""

import json
import os
from pathlib import Path

from fastmcp import FastMCP

# ── Constants ──────────────────────────────────────────────────────────────────
BASE_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
PATTERNS_FILE = BASE_DIR / "threat_patterns.json"

VALID_CATEGORIES = {
    "direct_injection",
    "indirect_injection",
    "roleplay_jailbreak",
    "token_smuggling",
    "tool_hijacking",
}

# ── Load patterns once at startup (stateless, read-only) ──────────────────────
def _load_patterns() -> list[dict]:
    """Load threat patterns from JSON file. Raises on missing/corrupt file."""
    if not PATTERNS_FILE.exists():
        raise FileNotFoundError(
            f"[FAIL] threat_patterns.json not found at: {PATTERNS_FILE}"
        )
    with open(PATTERNS_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("patterns", [])


# Load once at import time — MCP server is read-only, no writes needed
_ALL_PATTERNS: list[dict] = _load_patterns()

print(f"[OK] MCP Server loaded {len(_ALL_PATTERNS)} threat patterns from {PATTERNS_FILE.name}")

# ── FastMCP Server Definition ─────────────────────────────────────────────────
mcp = FastMCP(
    name="neural-firewall-threat-intel",
    instructions=(
        "Threat intelligence server for Neural Firewall. "
        "Provides known prompt injection and attack signatures to ADK agents. "
        "Use get_patterns_by_category() for category-specific lookup. "
        "Use search_patterns() for keyword-based search across all patterns."
    ),
)


@mcp.tool()
def get_patterns_by_category(category: str) -> list[dict]:
    """
    Return all threat patterns for a specific attack category.

    Args:
        category: One of: direct_injection, indirect_injection,
                  roleplay_jailbreak, token_smuggling, tool_hijacking

    Returns:
        List of pattern objects with id, severity, pattern, description.
        Returns empty list if category is invalid (no error raised).
    """
    if category not in VALID_CATEGORIES:
        return []

    return [p for p in _ALL_PATTERNS if p.get("category") == category]


@mcp.tool()
def search_patterns(query: str) -> list[dict]:
    """
    Search all threat patterns for a keyword match in pattern text or description.

    Args:
        query: Keyword or phrase to search for (case-insensitive)

    Returns:
        List of matching pattern objects. Empty list if no matches.
        Capped at 10 results to prevent response bloat.
    """
    if not query or not query.strip():
        return []

    query_lower = query.lower().strip()
    matches = []

    for p in _ALL_PATTERNS:
        pattern_text = p.get("pattern", "").lower()
        description = p.get("description", "").lower()
        category = p.get("category", "").lower()

        if query_lower in pattern_text or query_lower in description or query_lower in category:
            matches.append(p)

        if len(matches) >= 10:
            break

    return matches


@mcp.tool()
def get_all_categories() -> list[str]:
    """
    Return the list of all valid threat categories in the database.

    Returns:
        List of category name strings.
    """
    return sorted(list(VALID_CATEGORIES))


@mcp.tool()
def get_pattern_by_id(pattern_id: str) -> dict | None:
    """
    Return a single pattern by its unique ID.

    Args:
        pattern_id: Pattern ID string (e.g., "DIR-001", "TOK-004")

    Returns:
        Pattern dict if found, None if not found.
    """
    for p in _ALL_PATTERNS:
        if p.get("id") == pattern_id:
            return p
    return None


# ── Entry Point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("[INFO] Starting Neural Firewall MCP Threat Intelligence Server...")
    print(f"[INFO] Categories available: {sorted(VALID_CATEGORIES)}")
    print("[INFO] Tools: get_patterns_by_category | search_patterns | get_all_categories | get_pattern_by_id")
    mcp.run()
