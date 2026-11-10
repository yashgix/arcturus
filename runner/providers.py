"""Provider request shapes and answer decoding. Kept outside the signed enforcement code so format fixes
need no new grant; llm.call still checks every body against the grant before sending."""

import re

from api_review import decode, encode
from research_reports import wire_schema

MAX_ANSWER = 4_000_000
PROVIDER = {"claude": "anthropic", "gpt": "openai", "deepseek": "deepseek"}


def strip_lengths(schema):
    if isinstance(schema, dict):
        return {k: strip_lengths(v) for k, v in schema.items() if k not in ("minLength", "maxLength")}
    if isinstance(schema, list):
        return [strip_lengths(v) for v in schema]
    return schema


def request(model, settings, system, packet, schema):
    provider = PROVIDER[model.split("-")[0]]
    content = encode(packet).decode()
    limit = settings["max_output_tokens"]
    if settings.get("json_by_instruction"):
        system += "\nReturn only one JSON object matching this schema: " + encode(strip_lengths(schema)).decode()
    if provider == "anthropic":
        output = {"effort": settings["effort"]}
        if not settings.get("json_by_instruction"):
            output["format"] = {"type": "json_schema", "schema": wire_schema(schema, provider)}
        return {
            "model": model,
            "max_tokens": limit,
            "system": system,
            "stream": False,
            "messages": [{"role": "user", "content": content}],
            "thinking": {"type": "adaptive"},
            "output_config": output,
        }
    if provider == "openai":
        return {
            "model": model,
            "instructions": system,
            "input": content,
            "max_output_tokens": limit,
            "store": False,
            "reasoning": {"effort": settings["effort"]},
            "text": {
                "format": {"type": "json_object"}
                if settings.get("json_by_instruction")
                else {"type": "json_schema", "name": "arcturus_step", "strict": True, "schema": strip_lengths(schema)}
            },
        }
    return {
        "model": model,
        "max_tokens": limit,
        "stream": False,
        "thinking": {"type": "enabled"},
        "reasoning_effort": settings["effort"],
        "messages": [
            {
                "role": "system",
                "content": system
                if settings.get("json_by_instruction")
                else system
                + "\nReturn only one JSON object matching this schema: "
                + encode(strip_lengths(schema)).decode(),
            },
            {"role": "user", "content": content},
        ],
    }


def json_object(text):
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        raise ValueError("no JSON object in the response")
    return decode(match[0].encode(), maximum=MAX_ANSWER)
