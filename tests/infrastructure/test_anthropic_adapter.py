# tests/infrastructure/test_anthropic_adapter.py

from unittest.mock import patch, MagicMock

import pytest
from aegis.infrastructure.adapters.anthropic_adapter import AnthropicAdapter
from aegis.domain.models import Vulnerability, Severity


class TestStripMarkdown:

    def test_strips_python_fence(self):
        raw = "```python\nprint('hello')\n```"
        assert AnthropicAdapter._strip_markdown(raw) == "print('hello')"

    def test_strips_generic_fence(self):
        raw = "```\nprint('hello')\n```"
        assert AnthropicAdapter._strip_markdown(raw) == "print('hello')"

    def test_passes_through_plain_code(self):
        raw = "print('hello')"
        assert AnthropicAdapter._strip_markdown(raw) == "print('hello')"

    def test_strips_surrounding_whitespace(self):
        raw = "  \n print('hello') \n  "
        assert AnthropicAdapter._strip_markdown(raw) == "print('hello')"


class TestCheckSyntax:

    def test_valid_code_returns_none(self):
        assert AnthropicAdapter._check_syntax("print('hello')") is None

    def test_multiline_valid_code(self):
        code = "x = 1\nif x:\n    print(x)"
        assert AnthropicAdapter._check_syntax(code) is None

    def test_syntax_error_returns_message(self):
        result = AnthropicAdapter._check_syntax("print('hello'")
        assert result is not None
        assert "line 1" in result

    def test_indentation_error_returns_message(self):
        result = AnthropicAdapter._check_syntax("if True:\nprint('bad')")
        assert result is not None

    def test_unterminated_string_returns_message(self):
        result = AnthropicAdapter._check_syntax('x = "unterminated')
        assert result is not None


class TestGenerateExploitRetry:

    def _make_adapter(self):
        with patch("aegis.infrastructure.adapters.anthropic_adapter.Anthropic"):
            adapter = AnthropicAdapter(api_key="test-key")
        return adapter

    def _make_vuln(self):
        return Vulnerability(
            id="V-1", cwe_id="CWE-89", title="SQL Injection",
            description="test", severity=Severity.HIGH,
        )

    def test_valid_code_no_retry(self):
        adapter = self._make_adapter()
        valid_code = "print('VULNERABILITY CONFIRMED')"
        adapter.client.messages.create = MagicMock(
            return_value=MagicMock(content=[MagicMock(text=valid_code)])
        )

        result = adapter.generate_exploit_script(self._make_vuln(), "target")

        assert result == valid_code
        assert adapter.client.messages.create.call_count == 1

    def test_syntax_error_triggers_retry(self):
        adapter = self._make_adapter()
        bad_code = "print('hello'"
        fixed_code = "print('hello')"
        adapter.client.messages.create = MagicMock(
            side_effect=[
                MagicMock(content=[MagicMock(text=bad_code)]),
                MagicMock(content=[MagicMock(text=fixed_code)]),
            ]
        )

        result = adapter.generate_exploit_script(self._make_vuln(), "target")

        assert result == fixed_code
        assert adapter.client.messages.create.call_count == 2

    def test_retry_includes_error_in_prompt(self):
        adapter = self._make_adapter()
        bad_code = "print('hello'"
        adapter.client.messages.create = MagicMock(
            side_effect=[
                MagicMock(content=[MagicMock(text=bad_code)]),
                MagicMock(content=[MagicMock(text="print('hello')")]),
            ]
        )

        adapter.generate_exploit_script(self._make_vuln(), "target")

        retry_call = adapter.client.messages.create.call_args_list[1]
        messages = retry_call.kwargs["messages"]
        assert len(messages) == 3
        assert "syntax error" in messages[2]["content"].lower()

    def test_both_attempts_fail_returns_last(self):
        adapter = self._make_adapter()
        bad_code_1 = "print('hello'"
        bad_code_2 = "print('world'"
        adapter.client.messages.create = MagicMock(
            side_effect=[
                MagicMock(content=[MagicMock(text=bad_code_1)]),
                MagicMock(content=[MagicMock(text=bad_code_2)]),
            ]
        )

        result = adapter.generate_exploit_script(self._make_vuln(), "target")

        assert result == bad_code_2
        assert adapter.client.messages.create.call_count == 2

    def test_markdown_stripped_before_syntax_check(self):
        adapter = self._make_adapter()
        fenced = "```python\nprint('hello')\n```"
        adapter.client.messages.create = MagicMock(
            return_value=MagicMock(content=[MagicMock(text=fenced)])
        )

        result = adapter.generate_exploit_script(self._make_vuln(), "target")

        assert result == "print('hello')"
        assert adapter.client.messages.create.call_count == 1
