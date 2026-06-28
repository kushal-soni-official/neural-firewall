"""
Neural Firewall — Firewall Pipeline
Orchestrates all 5 agents in sequence using Google ADK.

Flow:
  raw_input -> Intake -> Inspection -> Probe -> [HITL?] -> Output Sanitizer -> safe_response

Entry point: await FirewallPipeline.run(user_input, agent_response)
"""

import os
import sys
import json
import asyncio
import time
from pathlib import Path
from typing import Any
from dotenv import load_dotenv

# Add project root to sys.path so 'agents', 'memory', etc. are importable
_PROJECT_ROOT = Path(__file__).parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# CRITICAL: load_dotenv BEFORE any google.adk import
_ENV_PATH = _PROJECT_ROOT / ".env"
load_dotenv(dotenv_path=_ENV_PATH)

from google.adk.agents import LlmAgent, SequentialAgent  # noqa: E402
from google.adk.sessions import InMemorySessionService               # noqa: E402
from google.adk.runners import Runner                                # noqa: E402
from google.genai import types as genai_types                        # noqa: E402

from agents.intake_agent import (  # noqa: E402
    create_intake_agent,
    preprocess_input,
)
from agents.inspection_agent import (  # noqa: E402
    create_inspection_agent,
    parse_inspection_result,
)
from agents.probe_agent import (  # noqa: E402
    create_probe_agent,
    build_probe_prompt,
    parse_probe_result,
)
from agents.hitl_agent import (  # noqa: E402
    create_hitl_request,
    wait_for_decision,
)
from agents.output_sanitizer import (  # noqa: E402
    create_output_sanitizer_agent,
    build_sanitizer_prompt,
    parse_sanitizer_result,
    quick_local_sanitize,
    BLOCKED_RESPONSE_MESSAGE,
)

# ── Constants ──────────────────────────────────────────────────────────────────
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
APP_NAME = "neural-firewall"

# Threshold below which we skip the Probe Agent (clearly clean input)
SKIP_PROBE_THRESHOLD = 0.40


class PipelineResult:
    """Structured result object returned by FirewallPipeline.run()"""

    def __init__(self):
        self.request_id: str = ""
        self.original_input: str = ""
        self.final_decision: str = "block"           # "allow" | "block" | "hitl_approved" | "hitl_denied"
        self.threat_score: float = 0.0
        self.category: str = "unknown"
        self.sanitized_response: str = BLOCKED_RESPONSE_MESSAGE
        self.hitl_triggered: bool = False
        self.hitl_decision: str = ""
        self.pipeline_log: list[dict] = []           # Full trace for ADK demo
        self.processing_time_ms: int = 0
        self.error: str = ""

    def to_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "original_input": self.original_input[:200],  # truncate for API response
            "final_decision": self.final_decision,
            "threat_score": self.threat_score,
            "category": self.category,
            "sanitized_response": self.sanitized_response,
            "hitl_triggered": self.hitl_triggered,
            "hitl_decision": self.hitl_decision,
            "pipeline_log": self.pipeline_log,
            "processing_time_ms": self.processing_time_ms,
            "error": self.error,
        }


async def _run_llm_agent(
    agent: LlmAgent,
    prompt: str,
    session_service: InMemorySessionService,
    session_id: str,
    user_id: str = "firewall-system",
) -> str:
    """
    Helper: run a single LlmAgent and return its text response.
    Uses ADK Runner for proper session + event handling.
    """
    runner = Runner(
        agent=agent,
        app_name=APP_NAME,
        session_service=session_service,
    )

    content = genai_types.Content(
        role="user",
        parts=[genai_types.Part(text=prompt)],
    )

    response_text = ""
    async for event in runner.run_async(
        user_id=user_id,
        session_id=session_id,
        new_message=content,
    ):
        if event.is_final_response() and event.content:
            for part in event.content.parts:
                if hasattr(part, "text") and part.text:
                    response_text += part.text

    return response_text.strip()


class FirewallPipeline:
    """
    Main orchestrator for the Neural Firewall 5-agent pipeline.
    Thread-safe: each run() call gets its own session_id.
    """

    def __init__(self):
        self.session_service = InMemorySessionService()

        # Instantiate agents once — reused across requests
        self.intake_agent = create_intake_agent()
        self.inspection_agent = create_inspection_agent()
        self.probe_agent = create_probe_agent()
        self.output_sanitizer = create_output_sanitizer_agent()

        print("[OK] FirewallPipeline initialized with all 5 agents")

    async def run(
        self,
        user_input: str,
        agent_response: str = "",
        session_id: str | None = None,
    ) -> PipelineResult:
        """
        Execute the full 5-agent security pipeline.

        Args:
            user_input: Raw text from the user/external source to analyze
            agent_response: The protected AI agent's response to sanitize (can be empty)
            session_id: Optional — if None, a new session is created

        Returns:
            PipelineResult with full trace and decision
        """
        start_time = time.time()
        result = PipelineResult()
        result.original_input = user_input

        # Generate unique session ID for this request
        import uuid
        sid = session_id or str(uuid.uuid4())
        result.request_id = sid

        try:
            # ── STAGE 1: LOCAL INTAKE PREPROCESSING ──────────────────────────
            print(f"[PIPELINE] [{sid[:8]}] Stage 1: Intake preprocessing...")

            intake_local = preprocess_input(user_input)
            cleaned_text = intake_local["cleaned_text"]

            # Also run LLM-based intake for encoded payload detection
            intake_llm_response = await _run_llm_agent(
                agent=self.intake_agent,
                prompt=(
                    f"Analyze and normalize this input text:\n\n{user_input}\n\n"
                    f"Local preprocessing already detected: {intake_local['normalization_log']}\n"
                    f"Cleaned version so far: {cleaned_text}\n\n"
                    f"Now check for any remaining encoding (base64, rot13, hex) and respond with JSON."
                ),
                session_service=self.session_service,
                session_id=sid,
            )

            intake_result = intake_local.copy()
            intake_result["llm_analysis"] = intake_llm_response

            result.pipeline_log.append({
                "stage": "intake",
                "input": user_input[:200],
                "cleaned": cleaned_text[:200],
                "log": intake_local["normalization_log"],
                "significant_change": intake_local["significant_change"],
            })

            print(f"[PIPELINE] [{sid[:8]}] Stage 1 complete. Encoding: {intake_local['encoding_detected']}")

            # ── STAGE 2: INSPECTION AGENT (with MCP call) ────────────────────
            print(f"[PIPELINE] [{sid[:8]}] Stage 2: Inspection Agent (MCP threat lookup)...")

            inspection_prompt = (
                f"Analyze this input for prompt injection threats.\n\n"
                f"ORIGINAL INPUT: {user_input}\n\n"
                f"CLEANED/DECODED INPUT: {cleaned_text}\n\n"
                f"Note: Significant encoding was detected: {intake_local['significant_change']}\n\n"
                f"Call get_patterns_by_category() for each category first, then analyze and respond with JSON."
            )

            inspection_response = await _run_llm_agent(
                agent=self.inspection_agent,
                prompt=inspection_prompt,
                session_service=self.session_service,
                session_id=sid,
            )

            inspection_result = parse_inspection_result(inspection_response)
            threat_score = inspection_result["threat_score"]
            result.threat_score = threat_score
            result.category = inspection_result.get("category", "unknown")

            result.pipeline_log.append({
                "stage": "inspection",
                "threat_score": threat_score,
                "category": inspection_result.get("category"),
                "confidence": inspection_result.get("confidence"),
                "reasoning": inspection_result.get("reasoning", "")[:300],
                "matched_patterns": inspection_result.get("matched_patterns", []),
                "requires_probe": inspection_result.get("requires_probe", False),
                "requires_hitl": inspection_result.get("requires_hitl", False),
            })

            print(f"[PIPELINE] [{sid[:8]}] Stage 2 complete. Score: {threat_score:.2f}, Category: {result.category}")

            # ── EARLY EXIT: CLEARLY CLEAN INPUT ──────────────────────────────
            if threat_score < SKIP_PROBE_THRESHOLD and not intake_local["significant_change"]:
                print(f"[PIPELINE] [{sid[:8]}] Input is clean (score {threat_score:.2f} < {SKIP_PROBE_THRESHOLD}). Skipping probe.")
                result.final_decision = "allow"
                result.pipeline_log.append({"stage": "probe", "skipped": True, "reason": "score below threshold"})

                # Still run output sanitizer on the agent's response
                goto_sanitizer = True
                probe_result = {
                    "final_score": threat_score,
                    "requires_human": False,
                    "verdict": "allow",
                    "probe_reasoning": "Skipped — input below threat threshold.",
                    "final_reasoning": "Input classified as clean.",
                }
            else:
                # ── STAGE 3: PROBE AGENT ─────────────────────────────────────
                print(f"[PIPELINE] [{sid[:8]}] Stage 3: Probe Agent (red-team analysis)...")

                probe_prompt = build_probe_prompt(cleaned_text, inspection_result)
                probe_response = await _run_llm_agent(
                    agent=self.probe_agent,
                    prompt=probe_prompt,
                    session_service=self.session_service,
                    session_id=sid,
                )

                probe_result = parse_probe_result(probe_response, original_score=threat_score)
                final_score = probe_result.get("final_score", threat_score)
                result.threat_score = final_score  # Update to probe-adjusted score

                result.pipeline_log.append({
                    "stage": "probe",
                    "probe_score": probe_result.get("probe_score"),
                    "final_score": final_score,
                    "disagreement_gap": probe_result.get("disagreement_gap"),
                    "requires_human": probe_result.get("requires_human"),
                    "verdict": probe_result.get("verdict"),
                    "probe_reasoning": probe_result.get("probe_reasoning", "")[:300],
                })

                print(f"[PIPELINE] [{sid[:8]}] Stage 3 complete. Final score: {final_score:.2f}, HITL needed: {probe_result.get('requires_human')}")
                goto_sanitizer = True

            # ── STAGE 4: HITL GATE (CONDITIONAL) ────────────────────────────
            if probe_result.get("requires_human", False):
                print(f"[PIPELINE] [{sid[:8]}] Stage 4: HITL triggered. Waiting for human decision...")
                result.hitl_triggered = True

                hitl_rid = create_hitl_request(
                    original_input=user_input,
                    intake_result=intake_result,
                    inspection_result=inspection_result,
                    probe_result=probe_result,
                )

                result.pipeline_log.append({
                    "stage": "hitl",
                    "triggered": True,
                    "hitl_request_id": hitl_rid,
                    "status": "waiting",
                })

                # Block pipeline here until human decides (or timeout)
                decision = await wait_for_decision(hitl_rid)
                result.hitl_decision = decision

                result.pipeline_log[-1]["status"] = "resolved"
                result.pipeline_log[-1]["decision"] = decision

                if decision == "deny":
                    print(f"[PIPELINE] [{sid[:8]}] HITL: DENIED. Blocking request.")
                    result.final_decision = "hitl_denied"
                    result.sanitized_response = BLOCKED_RESPONSE_MESSAGE
                    result.processing_time_ms = int((time.time() - start_time) * 1000)
                    return result
                else:
                    print(f"[PIPELINE] [{sid[:8]}] HITL: APPROVED. Continuing pipeline.")
                    result.final_decision = "hitl_approved"

            else:
                # No HITL needed
                result.pipeline_log.append({"stage": "hitl", "triggered": False})
                verdict = probe_result.get("verdict", "block")
                if verdict == "allow" or threat_score < SKIP_PROBE_THRESHOLD:
                    result.final_decision = "allow"
                else:
                    result.final_decision = "block"
                    result.sanitized_response = BLOCKED_RESPONSE_MESSAGE
                    result.processing_time_ms = int((time.time() - start_time) * 1000)
                    print(f"[PIPELINE] [{sid[:8]}] Blocked by probe verdict: {verdict}")
                    return result

            # ── STAGE 5: OUTPUT SANITIZER ────────────────────────────────────
            if agent_response:
                print(f"[PIPELINE] [{sid[:8]}] Stage 5: Output sanitizer...")

                # Fast local check first
                local_check = quick_local_sanitize(agent_response)
                if local_check:
                    sanitizer_result = local_check
                else:
                    sanitizer_prompt = build_sanitizer_prompt(user_input, agent_response)
                    sanitizer_response = await _run_llm_agent(
                        agent=self.output_sanitizer,
                        prompt=sanitizer_prompt,
                        session_service=self.session_service,
                        session_id=sid,
                    )
                    sanitizer_result = parse_sanitizer_result(sanitizer_response, agent_response)

                result.sanitized_response = sanitizer_result.get("sanitized_response", agent_response)
                result.pipeline_log.append({
                    "stage": "output_sanitizer",
                    "safe": sanitizer_result.get("safe", True),
                    "intervention": sanitizer_result.get("intervention_type", "none"),
                    "issues": sanitizer_result.get("issues_found", []),
                })
                print(f"[PIPELINE] [{sid[:8]}] Stage 5 complete. Safe: {sanitizer_result.get('safe')}, Intervention: {sanitizer_result.get('intervention_type')}")
            else:
                result.sanitized_response = "[Neural Firewall] Input analyzed. No agent response to sanitize."
                result.pipeline_log.append({"stage": "output_sanitizer", "skipped": True, "reason": "no agent_response provided"})

        except Exception as e:
            # CRITICAL: Any unhandled exception = BLOCK the request (fail-safe, never fail-open)
            print(f"[FAIL] Pipeline exception for session {sid[:8]}: {e}")
            result.final_decision = "block"
            result.sanitized_response = BLOCKED_RESPONSE_MESSAGE
            result.error = str(e)
            result.pipeline_log.append({"stage": "error", "message": str(e)})

        result.processing_time_ms = int((time.time() - start_time) * 1000)
        print(f"[PIPELINE] [{sid[:8]}] Complete. Decision: {result.final_decision} | Time: {result.processing_time_ms}ms")
        return result


# ── Module-level singleton (initialized once by FastAPI on startup) ────────────
_pipeline_instance: FirewallPipeline | None = None


def get_pipeline() -> FirewallPipeline:
    """Return the module-level pipeline singleton. Initialize if needed."""
    global _pipeline_instance
    if _pipeline_instance is None:
        _pipeline_instance = FirewallPipeline()
    return _pipeline_instance


# ── Standalone test ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    async def _test():
        print("[INFO] FirewallPipeline standalone test (no LLM calls)...")

        # Test PipelineResult serialization
        r = PipelineResult()
        r.request_id = "test-123"
        r.final_decision = "block"
        r.threat_score = 0.95
        r.category = "direct_injection"
        r.pipeline_log = [{"stage": "intake", "log": ["test"]}]
        d = r.to_dict()
        assert d["final_decision"] == "block"
        assert d["threat_score"] == 0.95
        print("[OK] PipelineResult.to_dict() works")

        # Test get_pipeline singleton
        p1 = get_pipeline()
        p2 = get_pipeline()
        assert p1 is p2
        print("[OK] get_pipeline() singleton works")

        print("\n[PASS] Pipeline module verified")

    asyncio.run(_test())
