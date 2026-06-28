import sys
print("Python:", sys.version)
results = {}

packages = {
    "google.adk": "google.adk",
    "fastapi": "fastapi",
    "uvicorn": "uvicorn",
    "dotenv (python-dotenv)": "dotenv",
    "fastmcp": "fastmcp",
    "pytest": "pytest",
    "sqlite3 (built-in)": "sqlite3",
    "asyncio (built-in)": "asyncio",
    "opentelemetry.api": "opentelemetry.api",
    "pydantic": "pydantic",
    "httpx": "httpx",
    "mcp": "mcp",
    "google.genai": "google.genai",
    "starlette": "starlette",
}

for label, mod in packages.items():
    try:
        __import__(mod)
        results[label] = "OK"
    except ImportError as e:
        results[label] = f"FAIL - {e}"

print("\n--- IMPORT VERIFICATION RESULTS ---")
for k, v in results.items():
    status = "[OK]  " if v == "OK" else "[FAIL]"
    print(f"  {status} {k}: {v}")

all_ok = all(v == "OK" for v in results.values())
print(f"\n{'ALL IMPORTS PASSED' if all_ok else 'SOME IMPORTS FAILED'}")
