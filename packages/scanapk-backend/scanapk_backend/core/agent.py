import json
import os
import re

from scanapk_backend.core.knowledge_graph import build_graph
from scanapk_backend.core.models import get_models
from scanapk_backend.core.tools import TOOL_DEFINITIONS, execute_tool

_SYSTEM_PROMPT = """You are a mobile malware analyst at a bank's cybersecurity team.
You have access to Android APK analysis tools.

Use Chain-of-Thought reasoning. Always structure your analysis in three phases:

## Phase 1: Catalog
List every finding from the knowledge graph — permissions, APIs, URLs, IPs, components, dynamic hits.

## Phase 2: Reason
Analyze what each finding means. Ask yourself:
- What can this permission/API enable?
- Which findings form a dangerous combination?
- What threat category does each pattern match?

## Phase 3: Assess
Score and classify based on your reasoning above.

The knowledge graph contains all available static and dynamic evidence.
TECH entries flag known evasion techniques detected during monitoring (e.g. Delayed Execution, Dropper/Two-Stage, Payload Download).

**Evasion Detection Guidance:**
- `Delayed Execution`: Look for timers, Thread.sleep, postDelayed, UI event listeners (OnClickListener) followed by suspicious activity. This means the malware waits for human interaction before activating.
- `Dropper / Two-Stage`: Look for InMemoryDexClassLoader, DexClassLoader loading from network paths, or Class.forName + Method.invoke patterns. This means the clean APK downloads malicious code at runtime.
- `Payload Download`: Look for DownloadManager requests or large HTTP responses (>10KB). The app may be fetching encrypted/encoded payloads from a C2 server.

Call tools only if you need deeper investigation beyond what is provided.
Once you have sufficient information, call `finalize_assessment` with valid JSON:

{
  "malware_family": <string or null>,
  "threat_types": [<string>],
  "iocs": { "urls": [<string>], "ips": [<string>], "apis": [<string>] },
  "key_findings": [<string>],
  "recommendations": [<string>],
  "confidence": "LOW" | "MEDIUM" | "HIGH"
}

IMPORTANT: A deterministic risk assessment has already been calculated and is
provided in the knowledge graph as RISK entries. Do NOT recalculate the score
or severity — those are already set. Your job is to:
  1. Validate whether the deterministic assessment is accurate.
  2. Identify the malware family and threat types.
  3. Enrich the explanation with key findings and recommendations.
  4. Flag any IOCs (URLs, IPs, APIs) for threat intelligence.
Be conservative — a banking app legitimately needs INTERNET + READ_PHONE_STATE.

IMPORTANT: Always show your step-by-step reasoning in the message content before calling any tool. Your reasoning is visible to the user."""


def analyse(
    apk_path: str,
    static_info: dict,
    evidence: dict | None = None,
    deterministic: dict | None = None,
    max_tool_rounds: int = 20,
    verbose: bool = True,
) -> dict:
    from openai import APIStatusError, OpenAI

    models = get_models()
    if not models:
        return _error("No API keys configured")

    clients: list[tuple[OpenAI, str]] = []
    for model_id, key_env in models:
        key = os.environ.get(key_env)
        if key:
            clients.append(
                (
                    OpenAI(
                        base_url="https://openrouter.ai/api/v1",
                        api_key=key,
                        default_headers={
                            "HTTP-Referer": "https://github.com/scanapk",
                            "X-Title": "ScanAPK",
                        },
                    ),
                    model_id,
                )
            )

    if not clients:
        return _error("No API keys configured")

    tools = TOOL_DEFINITIONS + [_FINALIZE_TOOL]

    kg = build_graph(apk_path, static_info, evidence, deterministic)
    msgs = [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {
            "role": "user",
            "content": f"Analyse this APK for malware indicators:\n\n{kg}",
        },
    ]

    for _ in range(max_tool_rounds):
        resp = None
        for client, model_id in clients:
            try:
                resp = client.chat.completions.create(
                    model=model_id,
                    messages=msgs,
                    tools=tools,
                    temperature=0.1,
                    max_tokens=8192,
                )
                break
            except APIStatusError as e:
                if e.status_code == 402:
                    continue
                return _error(str(e))
            except Exception as e:
                return _error(str(e))

        if resp is None:
            return _error(
                "All models exhausted — no credits available for any provider"
            )

        msg = resp.choices[0].message
        msgs.append(msg)

        if msg.content and verbose:
            print(f"\n  {msg.content}")

        if not msg.tool_calls:
            return _try_extract_report(msg.content)

        for tc in msg.tool_calls:
            fn = tc.function
            if fn.name == "finalize_assessment":
                if verbose:
                    print("\n  [Finalizing assessment...]")
                try:
                    args = json.loads(fn.arguments)
                    raw = args.get("report", {})
                except (json.JSONDecodeError, KeyError) as e:
                    return _error(f"Invalid finalize_assessment call: {e}")

                if isinstance(raw, str):
                    try:
                        return json.loads(raw)
                    except json.JSONDecodeError:
                        pass
                    try:
                        import ast

                        return ast.literal_eval(raw)
                    except (ValueError, SyntaxError):
                        pass
                    fixed = (
                        raw.replace("'", '"')
                        .replace("None", "null")
                        .replace("True", "true")
                        .replace("False", "false")
                    )
                    try:
                        return json.loads(fixed)
                    except json.JSONDecodeError:
                        pass
                    return _error(f"Could not parse report JSON:\n{raw[:300]}")
                return raw

            args = json.loads(fn.arguments) if fn.arguments else {}
            if verbose:
                args_str = ", ".join(f"{k}={v!r}" for k, v in args.items())
                print(f"\n  > Calling tool: {fn.name}({args_str})")
            result = execute_tool(fn.name, apk_path, **args)
            if verbose:
                print(f"  < Result: {result[:200]}{'...' if len(result) > 200 else ''}")
            msgs.append(
                {
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": result,
                }
            )

    return _error("Agent reached max tool call rounds without finalizing.")


_FINALIZE_TOOL = {
    "type": "function",
    "function": {
        "name": "finalize_assessment",
        "description": "Call this when you have enough evidence to produce the final structured assessment.",
        "parameters": {
            "type": "object",
            "properties": {
                "report": {
                    "type": "string",
                    "description": "JSON string matching the required schema with risk_score, severity, etc.",
                },
            },
            "required": ["report"],
        },
    },
}


def _try_extract_report(content: str) -> dict:
    if not content:
        return _error("Agent returned empty response")
    content = re.sub(r"^```[a-z]*\n?", "", content.strip())
    content = re.sub(r"\n?```$", "", content)
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        brace_start = content.find("{")
        brace_end = content.rfind("}")
        if brace_start >= 0 and brace_end > brace_start:
            try:
                return json.loads(content[brace_start : brace_end + 1])
            except json.JSONDecodeError:
                pass
        return _error(f"Could not parse JSON from model output. Raw:\n{content[:500]}")


def _error(msg: str) -> dict:
    return {
        "risk_score": -1,
        "severity": "ERROR",
        "malware_family": None,
        "threat_types": [],
        "iocs": {"urls": [], "ips": [], "apis": []},
        "key_findings": [msg],
        "recommendations": ["Fix the error above and retry."],
        "confidence": "LOW",
    }
