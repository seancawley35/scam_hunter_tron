"""Thin async wrapper around the Anthropic API that returns parsed JSON."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re

log = logging.getLogger("hunter.llm")


def parse_json(text: str) -> dict:
    text = re.sub(r"```(?:json)?", "", text)
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        raise ValueError("no JSON object in model output")
    return json.loads(text[start:end + 1])


class LLM:
    def __init__(self, model: str | None = None):
        self.model = model or os.getenv("HUNTER_MODEL", "claude-sonnet-5-5")
        self.enabled = bool(os.getenv("ANTHROPIC_API_KEY"))
        self.client = None
        self.calls = 0
        if self.enabled:
            from anthropic import AsyncAnthropic
            self.client = AsyncAnthropic(max_retries=3)

    async def json(self, system: str, user: str, max_tokens: int = 800) -> dict | None:
        if not self.enabled:
            return None
        last = None
        for attempt in range(3):
            try:
                self.calls += 1
                msg = await self.client.messages.create(
                    model=self.model, max_tokens=max_tokens, system=system,
                    messages=[{"role": "user", "content": user}],
                )
                return parse_json("".join(b.text for b in msg.content if b.type == "text"))
            except Exception as e:  # parse errors and API errors both retry
                last = e
                await asyncio.sleep(2 * (attempt + 1))
        log.warning("LLM call failed after retries: %s", last)
        return None
