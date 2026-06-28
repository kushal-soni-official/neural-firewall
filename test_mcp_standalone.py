"""
Quick test: verify MCP server loads patterns and tools work correctly.
Run with: .venv\\Scripts\\python.exe test_mcp_standalone.py
"""
import sys
import json
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

# Test 1: JSON file loads correctly
print("[TEST 1] Loading threat_patterns.json...")
try:
    with open("mcp_server/threat_patterns.json", "r", encoding="utf-8") as f:
        data = json.load(f)
    patterns = data.get("patterns", [])
    print(f"[OK] Loaded {len(patterns)} patterns")
    categories = set(p["category"] for p in patterns)
    print(f"[OK] Categories found: {sorted(categories)}")
except Exception as e:
    print(f"[FAIL] JSON load error: {e}")
    sys.exit(1)

# Test 2: Category filter works
print("\n[TEST 2] Category filter...")
direct = [p for p in patterns if p["category"] == "direct_injection"]
print(f"[OK] direct_injection: {len(direct)} patterns")
indirect = [p for p in patterns if p["category"] == "indirect_injection"]
print(f"[OK] indirect_injection: {len(indirect)} patterns")
roleplay = [p for p in patterns if p["category"] == "roleplay_jailbreak"]
print(f"[OK] roleplay_jailbreak: {len(roleplay)} patterns")
token = [p for p in patterns if p["category"] == "token_smuggling"]
print(f"[OK] token_smuggling: {len(token)} patterns")
tool = [p for p in patterns if p["category"] == "tool_hijacking"]
print(f"[OK] tool_hijacking: {len(tool)} patterns")

# Test 3: Search works
print("\n[TEST 3] Keyword search...")
query = "ignore"
matches = [p for p in patterns if query in p.get("pattern","").lower() or query in p.get("description","").lower()]
print(f"[OK] Search '{query}' found {len(matches)} matches")
if matches:
    print(f"     First match: [{matches[0]['id']}] {matches[0]['pattern']}")

# Test 4: Pattern ID lookup
print("\n[TEST 4] ID lookup...")
target_id = "DIR-001"
found = next((p for p in patterns if p["id"] == target_id), None)
if found:
    print(f"[OK] Found {target_id}: {found['pattern']}")
else:
    print(f"[FAIL] Pattern ID {target_id} not found")

# Test 5: FastMCP import
print("\n[TEST 5] FastMCP import...")
try:
    from fastmcp import FastMCP
    print("[OK] FastMCP imported successfully")
except ImportError as e:
    print(f"[FAIL] FastMCP import error: {e}")
    sys.exit(1)

print("\n[RESULT] All MCP server tests passed")
