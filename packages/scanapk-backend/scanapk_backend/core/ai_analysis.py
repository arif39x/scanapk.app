import json
import os
import re

from openai import OpenAI

from scanapk_backend.core.knowledge_graph import build_graph
from scanapk_backend.core.models import get_models

_SYSTEM_PROMPT = """You are a mobile malware analyst at a bank's cybersecurity team.
You receive structured evidence from static and dynamic analysis of Android APK files
and must produce a precise, actionable threat assessment.

All evidence is provided below as a knowledge graph (APP/PERM/API/URL/IP/RECV/SVC/LIB/FRIDA/NET/LOGCAT triples).

Always respond with valid JSON only — no markdown fences, no preamble.
Schema:
{
  "risk_score": <int 0-100>,
  "severity": "CLEAN" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "malware_family": <string or null>,
  "threat_types": [<list of strings>],
  "iocs": { "urls": [<string>], "ips": [<string>], "apis": [<string>] },
  "key_findings": [<3-7 strings>],
  "recommendations": [<3-5 strings>],
  "confidence": "LOW" | "MEDIUM" | "HIGH"
}

Risk score guidance:
  0-20   Clean or benign
  21-40  Suspicious, needs review
  41-60  Likely malicious
  61-80  High confidence malicious
  81-100 Confirmed malware / critical threat"""


def analyse(apk_path: str, static_info: dict, evidence: dict | None = None) -> dict:
    models = get_models()
    if not models:
        return _error("No API keys configured")

    kg = build_graph(apk_path, static_info, evidence)
    prompt = f"Analyse this Android APK evidence and return your assessment as JSON:\n\n{kg}"

    for model_id, key_env in models:
        key = os.environ.get(key_env)
        if not key:
            continue
        client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=key,
            default_headers={"HTTP-Referer": "https://github.com/scanapk", "X-Title": "ScanAPK"},
        )
        try:
            resp = client.chat.completions.create(
                model=model_id,
                messages=[
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.1,
                max_tokens=2048,
            )
            raw = resp.choices[0].message.content.strip()
            return _parse_json(raw)
        except Exception as e:
            err_str = str(e)
            if "402" in err_str or "credits" in err_str.lower():
                continue
            return _error(err_str)

    return _error("All models exhausted — no credits available for any provider")


def _parse_json(raw: str) -> dict:
    raw = re.sub(r"^```[a-z]*\n?", "", raw.strip())
    raw = re.sub(r"\n?```$", "", raw)
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        brace_start = raw.find("{")
        brace_end = raw.rfind("}")
        if brace_start >= 0 and brace_end > brace_start:
            try:
                return json.loads(raw[brace_start : brace_end + 1])
            except json.JSONDecodeError:
                pass
        return _error(f"Could not parse JSON from model output:\n{raw[:500]}")


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
