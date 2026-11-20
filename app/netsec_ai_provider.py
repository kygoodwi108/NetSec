#!/usr/bin/env python3
"""Provider adapter. Keeps legacy local Open WebUI/Ollama deployments compatible.

Only outbound requests to the configured assistant's chat endpoint are remapped.
This module never logs, stores, or forwards API credentials.
"""
import os

OPENAI_ORIGIN = 'https://api.openai.com'


def provider():
    result = os.getenv('NETSEC_AI_PROVIDER', 'openwebui').strip().lower()
    if result not in ('openai', 'openwebui'):
        raise ValueError('Unsupported NETSEC_AI_PROVIDER')
    return result


def settings():
    kind = provider()
    endpoint = os.getenv('NETSEC_AI_URL', os.getenv('OWUI_URL', '')).rstrip('/')
    key = os.getenv('NETSEC_AI_KEY', os.getenv('OWUI_KEY', '')).strip()
    model = os.getenv('NETSEC_AI_MODEL', os.getenv('OWUI_MODEL', '')).strip()
    if kind == 'openai' and endpoint != OPENAI_ORIGIN:
        raise ValueError('OpenAI provider requires https://api.openai.com')
    return endpoint, key, model


def adapt_chat_request(url, payload):
    """Adapt Open WebUI Chat Completions payload for OpenAI's API.

    OpenAI's public endpoint differs from Open WebUI, and not all model
    families accept `temperature`, `options`, or `max_tokens`.
    """
    if provider() != 'openai' or payload is None or not url.endswith('/api/chat/completions'):
        return url, payload
    if url != OPENAI_ORIGIN + '/api/chat/completions':
        raise ValueError('Refusing OpenAI key request to a non-OpenAI endpoint')
    body = dict(payload)
    body.pop('options', None)
    body.pop('temperature', None)
    if 'max_tokens' in body:
        body['max_completion_tokens'] = body.pop('max_tokens')
    return OPENAI_ORIGIN + '/v1/chat/completions', body
