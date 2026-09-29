import json
import httpx
from typing import Any

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
MODEL = "claude-sonnet-4-6"

SYSTEM_PROMPT = """You are a senior cloud security engineer.
You receive the JSON output of an automated cloud security scan.
You must respond with ONLY a valid JSON object — no markdown, no preamble.

The JSON must have exactly this shape:
{
  "risk_score": <integer 0-100>,
  "executive_summary": "<2-3 sentence plain-English summary of the overall security posture>",
  "findings": [
    {
      "severity": "critical|high|medium|low",
      "title": "<short title>",
      "explanation": "<why this is dangerous, in plain English>",
      "remediation_guidance": "<specific, actionable 2-4 sentence remediation guide for this exact finding>",
      "fix_cli": "<exact CLI command to fix this, or empty string if not applicable>",
      "cis_controls": ["<CIS control IDs referenced by this finding, copied from input>"]
    }
  ],
  "remediation_plans": {
    "CRITICAL": {
      "summary": "<1-2 sentence description of the critical risk theme>",
      "steps": ["<concrete action step 1>", "<concrete action step 2>", "<concrete action step 3>"],
      "estimated_effort": "<e.g. 2-4 hours>"
    },
    "HIGH": { "summary": "...", "steps": ["..."], "estimated_effort": "..." },
    "MEDIUM": { "summary": "...", "steps": ["..."], "estimated_effort": "..." },
    "LOW": { "summary": "...", "steps": ["..."], "estimated_effort": "..." }
  },
  "cis_mapping": {
    "<CIS control ID, e.g. CIS 1.8>": {
      "title": "<official short CIS control title>",
      "status": "FAIL",
      "findings_count": <integer>,
      "highest_severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "remediation_note": "<1 sentence on how to achieve compliance for this control>"
    }
  }
}

Rules:
- Sort findings by severity (critical first). Include at most 10 findings.
- Only include severity keys in remediation_plans that actually have findings.
- Remediation steps must be specific and actionable for the cloud provider in the scan.
- remediation_guidance per finding must be concrete — not generic. Reference the exact resource/config.
- fix_cli must use the correct cloud CLI (aws, az, gcloud) matching the scan provider.
- cis_mapping must include ALL unique CIS controls referenced across all findings in the input.
- estimated_effort is a rough human time estimate to remediate all findings at that severity level.
- If a fallback was used for a module, note the data limitation in the relevant finding's explanation."""


async def generate_ai_report(scan_result: dict[str, Any], api_key: str) -> dict[str, Any]:
    """Call Anthropic API and return structured report. Raises on failure."""
    user_message = f"Here is the AWS scan result:\n\n{json.dumps(scan_result, indent=2)}"

    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.post(
            ANTHROPIC_API_URL,
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": MODEL,
                "max_tokens": 4000,
                "system": SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": user_message}],
            },
        )
        response.raise_for_status()
        data = response.json()

    raw_text = data["content"][0]["text"]
    return json.loads(raw_text)


def get_anthropic_api_key() -> str:
    from app.core.config import settings
    if not settings.ANTHROPIC_API_KEY:
        raise ValueError("ANTHROPIC_API_KEY not set in .env")
    return settings.ANTHROPIC_API_KEY