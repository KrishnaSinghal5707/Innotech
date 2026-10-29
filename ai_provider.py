"""Backend-only AI transport shared by Q-Patch and future AI features."""
from __future__ import annotations
import json
import os
import urllib.error
import urllib.request
from typing import Protocol


class AIError(Exception):
    """Safe public error: never include provider bodies, headers or credentials."""


class AIProvider(Protocol):
    def generate_json(self, instructions: str, context: dict, schema: dict) -> dict: ...


class OpenAIProvider:
    """Responses API, bounded responses, no tools, redirects or automatic retries."""
    def __init__(self):
        self._key = os.environ.get('OPENAI_API_KEY', '').strip()
        self.model = os.environ.get('QSHIELD_AI_MODEL', '').strip()
        if not self._key or not self.model:
            raise AIError('Configure OPENAI_API_KEY and QSHIELD_AI_MODEL on the backend.')
        try:
            self.timeout = float(os.environ.get('QSHIELD_AI_TIMEOUT', '45'))
            if not 1 <= self.timeout <= 120:
                raise ValueError
        except ValueError:
            raise AIError('QSHIELD_AI_TIMEOUT must be between 1 and 120 seconds.') from None

    def generate_json(self, instructions: str, context: dict, schema: dict) -> dict:
        body = {'model': self.model, 'store': False, 'instructions': instructions,
                'input': json.dumps(context), 'max_output_tokens': 4000,
                'text': {'format': {'type': 'json_schema', 'name': 'qshield_proposal',
                                    'strict': True, 'schema': schema}}}
        request = urllib.request.Request('https://api.openai.com/v1/responses',
            data=json.dumps(body).encode(), headers={'Authorization': 'Bearer ' + self._key,
                                                     'Content-Type': 'application/json'})
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None
        try:
            with urllib.request.build_opener(NoRedirect).open(request, timeout=self.timeout) as response:
                raw = response.read(128_001)
            if len(raw) > 128_000:
                raise AIError('AI response exceeded the size limit.')
            result = json.loads(raw)
            if result.get('status') != 'completed':
                raise AIError('AI response was incomplete. No patch was generated.')
            parts = [part for item in result.get('output', []) if item.get('type') == 'message'
                     for part in item.get('content', [])]
            if any(p.get('type') == 'refusal' for p in parts):
                raise AIError('AI provider declined this request. No patch was generated.')
            text = ''.join(p.get('text', '') for p in parts if p.get('type') == 'output_text')
            if self._key in text:
                raise AIError('AI response contained sensitive material and was rejected.')
            value = json.loads(text)
            if not isinstance(value, dict):
                raise ValueError
            return value
        except AIError:
            raise
        except (urllib.error.URLError, OSError, ValueError, TypeError, KeyError, AttributeError):
            raise AIError('AI request failed or returned invalid data. Check backend configuration, access and connectivity.') from None


def configured_provider() -> AIProvider:
    if os.environ.get('QSHIELD_AI_PROVIDER', 'openai').lower() != 'openai':
        raise AIError('Unsupported QSHIELD_AI_PROVIDER. Currently supported: openai.')
    return OpenAIProvider()
