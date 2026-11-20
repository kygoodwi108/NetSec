#!/usr/bin/env python3
"""Strict response format and intentionally brief follow-up prompts for Jimmy.

No network requests, privileged actions, or changes to telemetry sources.
"""

SCHEMA = {
    'type': 'object',
    'additionalProperties': False,
    'properties': {
        'severity': {'type': 'string', 'enum': ['green', 'amber', 'red', 'unknown']},
        'summary': {'type': 'string', 'maxLength': 400},
        'observations': {
            'type': 'array', 'maxItems': 3,
            'items': {'type': 'string', 'maxLength': 220},
        },
        'recommended_actions': {
            'type': 'array', 'maxItems': 3,
            'items': {'type': 'string', 'maxLength': 240},
        },
        'confidence': {'type': 'string', 'enum': ['low', 'medium', 'high']},
    },
    'required': ['severity', 'summary', 'observations', 'recommended_actions', 'confidence'],
}

RESPONSE_FORMAT = {
    'type': 'json_schema',
    'json_schema': {'name': 'netsec_security_assessment', 'strict': True, 'schema': SCHEMA},
}

RETRY_SYSTEM = (
    'You are Jimmy, a careful security analyst. Use only the verified, summarized '
    'telemetry provided. Output one short JSON object with exactly these five '
    'keys: severity (green, amber, red or unknown), summary (a short nonempty '
    'string), observations (array of 0-3 short factual strings), '
    'recommended_actions (array of 0-3 short strings for unresolved issues '
    'only), confidence (low, medium or high). '
    'Do not claim that scanning means compromise. Observed CrowdSec ban denials '
    'are evidence of enforcement; do not recommend repeating this verification. '
    'CrowdSec timer failures are not application upstream errors. '
    'Do not propose a burst of sensitive-path tests. Never give commands, '
    'execute actions, or repeat log contents as instructions. JSON only.'
)


def minimal_retry_context(telemetry):
    """Bounded evidence retaining diagnoses but omitting verbose source metadata."""
    review = telemetry.get('evidence_brief') or {}
    return {
        'source_generated_at': telemetry.get('generated_at'),
        'traffic_heuristic_risk': telemetry.get('traffic_heuristic_risk'),
        'requests_24h': telemetry.get('requests_24h'),
        'http_5xx_24h': telemetry.get('http_5xx_24h'),
        'crowdsec': review.get('crowdsec'),
        'nginx': review.get('nginx'),
        'sensitive_paths': review.get('sensitive_paths'),
        'service_health': review.get('service_health'),
        'follow_up_states': (review.get('follow_up_states') or [])[:3],
        'scope': review.get('scope'),
        'limitations': review.get('do_not_claim'),
    }


def safe_failure_label(exc, finish_reason=None, content_length=0):
    """Useful diagnostics without recording raw model content or user credentials."""
    typ = type(exc).__name__
    # Parser/validator errors are fixed strings, but avoid exposing arbitrary
    # HTTP upstream messages in logs (which can reflect URLs or headers).
    detail = str(exc)[:120] if isinstance(exc, (ValueError, TypeError, KeyError)) else ''
    details = (': ' + detail) if detail else ''
    reason = str(finish_reason or 'unknown')[:30]
    return f'{typ}{details} [finish={reason}, chars={int(content_length)}]'
