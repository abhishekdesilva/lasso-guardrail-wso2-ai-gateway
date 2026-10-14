"""Mock Lasso Security guardrail API — PII detection/masking only.

Implements just enough of Lasso's real classify/classifix contract
(https://docs.lasso.security) for the lasso-guardrail gateway policy to
exercise its full request/response flow without a real Lasso account:

  POST {base}/classify   -> detect PII, report findings, do not rewrite content
  POST {base}/classifix  -> detect PII, report findings, AND return masked
                            `messages` (Lasso's own authoritative masked
                            content, which the gateway policy prefers over
                            applying findings' byte offsets itself)

Deliberately narrow: only PII detection (email, phone, SSN, credit card).
Lasso's real product also screens for jailbreaks, prompt injection, toxic
content, etc. — out of scope here, this mocks one deputy, not the product.

Stdlib only, so it runs in any bare `python:3-slim` image with no pip
install step.
"""

from __future__ import annotations

import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 8090

# (name, regex, mask token) — order matters: more specific patterns
# (credit card, SSN) must run before anything that could partially
# overlap a looser pattern.
PII_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("CREDIT_CARD", re.compile(r"\b(?:\d[ -]?){13,16}\b"), "[CREDIT_CARD_REDACTED]"),
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[SSN_REDACTED]"),
    ("EMAIL", re.compile(r"\b[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}\b"), "[EMAIL_REDACTED]"),
    ("PHONE", re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"), "[PHONE_REDACTED]"),
]

DEPUTY = "pii-deputy"


def find_pii(text: str) -> list[dict]:
    """Return non-overlapping PII spans, longest/first-pattern-wins on overlap."""
    spans: list[dict] = []
    claimed: list[tuple[int, int]] = []

    def overlaps(start: int, end: int) -> bool:
        return any(start < c_end and end > c_start for c_start, c_end in claimed)

    for name, pattern, mask in PII_PATTERNS:
        for m in pattern.finditer(text):
            start, end = m.start(), m.end()
            if overlaps(start, end):
                continue
            claimed.append((start, end))
            spans.append({"name": name, "start": start, "end": end, "mask": mask})

    spans.sort(key=lambda s: s["start"])
    return spans


def mask_content(text: str, spans: list[dict]) -> str:
    out = text
    for s in sorted(spans, key=lambda s: s["start"], reverse=True):
        out = out[: s["start"]] + s["mask"] + out[s["end"] :]
    return out


class Handler(BaseHTTPRequestHandler):
    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        path = self.path.rstrip("/")
        if not (path.endswith("/classify") or path.endswith("/classifix")):
            self._send_json(404, {"message": "not found"})
            return

        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            req = json.loads(raw)
        except json.JSONDecodeError:
            self._send_json(400, {"message": "invalid JSON body"})
            return

        messages = req.get("messages", [])
        do_mask = path.endswith("/classifix")

        findings: dict[str, list[dict]] = {}
        masked_messages = []
        violations = False

        for idx, msg in enumerate(messages):
            content = msg.get("content", "") or ""
            spans = find_pii(content)
            if spans:
                violations = True
                for s in spans:
                    findings.setdefault(DEPUTY, []).append(
                        {
                            "action": "AUTO_MASKING",
                            "name": s["name"],
                            "severity": "LOW",
                            "start": s["start"],
                            "end": s["end"],
                            "mask": s["mask"],
                            "message_index": idx,
                        }
                    )
            new_content = mask_content(content, spans) if (do_mask and spans) else content
            masked_messages.append({"role": msg.get("role", ""), "content": new_content})

        response = {"violations_detected": violations, "findings": findings}
        if do_mask:
            response["messages"] = masked_messages

        if violations:
            names = [s["name"] for msg in messages for s in find_pii(msg.get("content", "") or "")]
            print(f"[mock-lasso] {path}: PII found {names} -> masking={do_mask}")
            if do_mask:
                for orig, masked in zip(messages, masked_messages):
                    if orig.get("content") != masked["content"]:
                        print(f"[mock-lasso]   before: {orig.get('content')!r}")
                        print(f"[mock-lasso]   after:  {masked['content']!r}")
        else:
            print(f"[mock-lasso] {path}: no PII found, {len(messages)} message(s) clean")

        self._send_json(200, response)

    def log_message(self, fmt, *args):  # noqa: A002 — quiet, one-line access log
        print(f"[mock-lasso] {self.address_string()} {fmt % args}")


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"mock-lasso-server listening on :{PORT}")
    server.serve_forever()
