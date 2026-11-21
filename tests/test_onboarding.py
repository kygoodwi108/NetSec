"""Offline regression tests for the opt-in AI provider and setup wizard."""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'app'))
import netsec_ai_provider as adapter


class Onboarding(unittest.TestCase):
    def test_openai_endpoint_and_safe_payload(self):
        with patch.dict(os.environ, {'NETSEC_AI_PROVIDER': 'openai',
                                     'NETSEC_AI_URL': 'https://api.openai.com',
                                     'NETSEC_AI_MODEL': 'gpt-4.1-mini',
                                     'NETSEC_AI_KEY': 'sk-project-sample'}):
            self.assertEqual(adapter.settings(),
                             ('https://api.openai.com', 'sk-project-sample', 'gpt-4.1-mini'))
            u, p = adapter.adapt_chat_request(
                'https://api.openai.com/api/chat/completions',
                {'model': 'gpt-4.1-mini', 'options': {'think': False},
                 'max_tokens': 500, 'temperature': 0,
                 'messages': [{'role': 'user', 'content': 'test'}]})
            self.assertEqual(u, 'https://api.openai.com/v1/chat/completions')
            self.assertEqual(p['max_completion_tokens'], 500)
            self.assertNotIn('options', p)
            self.assertNotIn('max_tokens', p)
            self.assertNotIn('temperature', p)
            with self.assertRaises(ValueError):
                adapter.adapt_chat_request('https://evil.test/api/chat/completions',
                                           {'messages': []})

    def test_existing_openwebui_untouched(self):
        with patch.dict(os.environ, {'NETSEC_AI_PROVIDER': 'openwebui',
                                     'OWUI_URL': 'http://192.168.2.4:3000',
                                     'OWUI_KEY': 'private-local-key',
                                     'OWUI_MODEL': 'qwen3:8b'}, clear=True):
            self.assertEqual(adapter.settings(),
                             ('http://192.168.2.4:3000', 'private-local-key', 'qwen3:8b'))
            payload={'model': 'qwen3:8b', 'options': {'think': False}}
            url='http://192.168.2.4:3000/api/chat/completions'
            self.assertEqual(adapter.adapt_chat_request(url, payload), (url, payload))

    def test_invalid_provider_is_rejected(self):
        with patch.dict(os.environ, {'NETSEC_AI_PROVIDER': 'invalid'}):
            with self.assertRaises(ValueError):adapter.provider()

    def test_installer_safe_version_and_guardrails(self):
        script=(ROOT/'scripts/proxmox-setup.sh').read_text()
        self.assertIn('[[ ! -e "/etc/pve/lxc/${CTID}.conf" ]]', script)
        self.assertIn('ask_secret AI_KEY', script)
        self.assertIn('No', (ROOT/'docs/INSTALL_FROM_SCRATCH.md').read_text())
        self.assertIn('netsec-ban-worker.path', script)
        self.assertIn('1.4.0', (ROOT/'VERSION').read_text())
        p=subprocess.run(['bash',str(ROOT/'scripts/proxmox-setup.sh'),'--help'],
                         text=True,capture_output=True)
        self.assertEqual(p.returncode,0)
        self.assertIn('Static',p.stdout) if 'Static' in p.stdout else self.assertIn('static',p.stdout)

    def test_assistant_name_example(self):
        d=json.loads((ROOT/'config/config.json.example').read_text())
        self.assertEqual(d.get('assistant_name'), 'Jimmy')
        source=(ROOT/'app/app.py').read_text()
        self.assertIn("html.escape(ASSISTANT_NAME)",source)
        self.assertIn("replace('Jimmy', safe_name)",source)


if __name__ == '__main__': unittest.main()
