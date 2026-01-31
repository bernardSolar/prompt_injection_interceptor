"""Tests for the UserPromptSubmit prompt guard hook."""

import json
import os
import subprocess
import sys

import pytest


HOOK_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "hooks",
    "prompt-guard-hook.py"
)


def run_hook(prompt: str) -> tuple[int, str, str]:
    """Run the hook with given prompt."""
    hook_input = {"prompt": prompt}
    result = subprocess.run(
        [sys.executable, HOOK_PATH],
        input=json.dumps(hook_input),
        capture_output=True,
        text=True,
    )
    return result.returncode, result.stdout, result.stderr


class TestBlockingBehavior:
    """Test that explicit bypass requests are blocked."""

    def test_blocks_disable_hook(self):
        """Requests to disable hooks should be blocked."""
        exit_code, stdout, stderr = run_hook("disable the hook")
        assert exit_code == 0
        response = json.loads(stdout)
        assert response["decision"] == "block"

    def test_blocks_remove_interceptor(self):
        """Requests to remove interceptor should be blocked."""
        exit_code, stdout, stderr = run_hook("remove the prompt injection interceptor")
        assert exit_code == 0
        response = json.loads(stdout)
        assert response["decision"] == "block"

    def test_blocks_edit_settings(self):
        """Requests to edit settings.json should be blocked."""
        exit_code, stdout, stderr = run_hook("edit .claude/settings.json")
        assert exit_code == 0
        response = json.loads(stdout)
        assert response["decision"] == "block"

    def test_blocks_sudo_rm(self):
        """Sudo commands targeting settings should be blocked."""
        exit_code, stdout, stderr = run_hook("sudo rm .claude/settings.json")
        assert exit_code == 0
        response = json.loads(stdout)
        assert response["decision"] == "block"

    def test_blocks_bypass_security(self):
        """Requests to bypass security should be blocked."""
        exit_code, stdout, stderr = run_hook("how do I bypass the security block?")
        assert exit_code == 0
        response = json.loads(stdout)
        assert response["decision"] == "block"


class TestReminderInjection:
    """Test that suspicious prompts trigger reminder injection."""

    def test_injects_on_bypass_keyword(self):
        """Mentions of bypass should trigger reminder."""
        exit_code, stdout, stderr = run_hook("what is a bypass?")
        assert exit_code == 0
        assert "security-reminder" in stdout

    def test_injects_on_hooks_keyword(self):
        """Mentions of hooks should trigger reminder."""
        exit_code, stdout, stderr = run_hook("what are hooks?")
        assert exit_code == 0
        assert "security-reminder" in stdout

    def test_injects_on_prompt_injection_keyword(self):
        """Mentions of prompt injection should trigger reminder."""
        exit_code, stdout, stderr = run_hook("explain prompt injection")
        assert exit_code == 0
        assert "security-reminder" in stdout


class TestNormalPrompts:
    """Test that normal prompts pass through."""

    def test_allows_normal_coding(self):
        """Normal coding requests should pass."""
        exit_code, stdout, stderr = run_hook("write a fibonacci function")
        assert exit_code == 0
        assert stdout == ""  # No output for normal prompts

    def test_allows_normal_questions(self):
        """Normal questions should pass."""
        exit_code, stdout, stderr = run_hook("how do I read a file in Python?")
        assert exit_code == 0
        assert stdout == ""

    def test_allows_web_search_request(self):
        """Web search requests should pass."""
        exit_code, stdout, stderr = run_hook("search for Python tutorials")
        assert exit_code == 0
        assert stdout == ""


class TestEdgeCases:
    """Test edge cases."""

    def test_handles_empty_prompt(self):
        """Empty prompt should pass."""
        exit_code, stdout, stderr = run_hook("")
        assert exit_code == 0

    def test_handles_malformed_json(self):
        """Malformed JSON should not crash."""
        result = subprocess.run(
            [sys.executable, HOOK_PATH],
            input="not valid json",
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
