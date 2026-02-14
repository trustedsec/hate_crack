"""Unit tests for _pull_ollama_model helper, hcatOllama steps A-C, and ollama_attack handler."""

import io
import json
import os
import urllib.error
import urllib.request
from contextlib import contextmanager
from types import SimpleNamespace
from unittest import mock

import pytest

os.environ["HATE_CRACK_SKIP_INIT"] = "1"
from hate_crack import main as hc_main  # noqa: E402


# ---------------------------------------------------------------------------
# Shared test infrastructure
# ---------------------------------------------------------------------------

OLLAMA_URL = "http://localhost:11434"
MODEL = "llama3.2"


@pytest.fixture
def ollama_env(tmp_path):
    """Create the filesystem layout hcatOllama expects."""
    hash_file = tmp_path / "hashes.txt"
    hash_file.touch()

    wordlist = tmp_path / "sample.txt"
    wordlist.write_text("password\n123456\nletmein\n")

    return SimpleNamespace(
        tmp_path=tmp_path,
        hash_file=str(hash_file),
        wordlist=str(wordlist),
    )


@contextmanager
def ollama_globals(tmp_path, tuning="", potfile=""):
    """Patch the hc_main globals that hcatOllama reads."""
    rules_dir = str(tmp_path / "rules")
    os.makedirs(rules_dir, exist_ok=True)
    with mock.patch.object(hc_main, "ollamaUrl", OLLAMA_URL), \
         mock.patch.object(hc_main, "ollamaModel", MODEL), \
         mock.patch.object(hc_main, "hcatBin", "/usr/bin/hashcat"), \
         mock.patch.object(hc_main, "hcatTuning", tuning), \
         mock.patch.object(hc_main, "hcatPotfilePath", potfile), \
         mock.patch.object(hc_main, "hate_path", str(tmp_path)), \
         mock.patch.object(hc_main, "rulesDirectory", rules_dir), \
         mock.patch("hate_crack.main.generate_session_id", return_value="test_session"):
        yield


def _make_proc(wait_return=0):
    """Create a mock subprocess that works with both wait() and communicate()."""
    proc = mock.MagicMock()
    proc.wait.return_value = wait_return
    proc.communicate.return_value = (b"", b"")
    proc.returncode = wait_return
    return proc


def _generate_response(passwords):
    """Build a fake urlopen context-manager that returns an Ollama /api/generate JSON body."""
    body = json.dumps({"response": "\n".join(passwords)}).encode()
    resp = mock.MagicMock()
    resp.__enter__ = mock.Mock(return_value=io.BytesIO(body))
    resp.__exit__ = mock.Mock(return_value=False)
    return resp


def _urlopen_with_response(passwords):
    """Return a urlopen mock that always succeeds with the given passwords."""
    return mock.patch(
        "hate_crack.main.urllib.request.urlopen",
        return_value=_generate_response(passwords),
    )


# ---------------------------------------------------------------------------
# _pull_ollama_model tests
# ---------------------------------------------------------------------------

class TestPullOllamaModel:
    """Tests for _pull_ollama_model()."""

    OLLAMA_URL = "http://localhost:11434"
    MODEL = "llama3.2"

    def _make_stream_response(self, statuses):
        """Build a fake streaming response (newline-delimited JSON)."""
        lines = [json.dumps({"status": s}).encode() + b"\n" for s in statuses]
        return io.BytesIO(b"".join(lines))

    @mock.patch("hate_crack.main.urllib.request.urlopen")
    def test_successful_pull(self, mock_urlopen, capsys):
        mock_urlopen.return_value.__enter__ = mock.Mock(
            return_value=self._make_stream_response(
                ["pulling manifest", "downloading sha256:abc123", "success"]
            )
        )
        mock_urlopen.return_value.__exit__ = mock.Mock(return_value=False)

        result = hc_main._pull_ollama_model(self.OLLAMA_URL, self.MODEL)

        assert result is True
        captured = capsys.readouterr()
        assert "not found locally" in captured.out
        assert "Successfully pulled" in captured.out
        assert "pulling manifest" in captured.out

    @mock.patch("hate_crack.main.urllib.request.urlopen")
    def test_pull_http_error(self, mock_urlopen, capsys):
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="http://localhost:11434/api/pull",
            code=500,
            msg="Internal Server Error",
            hdrs=None,
            fp=None,
        )

        result = hc_main._pull_ollama_model(self.OLLAMA_URL, self.MODEL)

        assert result is False
        captured = capsys.readouterr()
        assert "HTTP 500" in captured.out

    @mock.patch("hate_crack.main.urllib.request.urlopen")
    def test_pull_url_error(self, mock_urlopen, capsys):
        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")

        result = hc_main._pull_ollama_model(self.OLLAMA_URL, self.MODEL)

        assert result is False
        captured = capsys.readouterr()
        assert "Could not connect" in captured.out

    @mock.patch("hate_crack.main.urllib.request.urlopen")
    def test_pull_generic_exception(self, mock_urlopen, capsys):
        mock_urlopen.side_effect = RuntimeError("unexpected")

        result = hc_main._pull_ollama_model(self.OLLAMA_URL, self.MODEL)

        assert result is False
        captured = capsys.readouterr()
        assert "unexpected" in captured.out

    @mock.patch("hate_crack.main.urllib.request.urlopen")
    def test_pull_handles_empty_status_lines(self, mock_urlopen, capsys):
        """Blank lines and missing status keys should not crash."""
        lines = b'{"status": "downloading"}\n\n{"other": "data"}\n'
        mock_urlopen.return_value.__enter__ = mock.Mock(
            return_value=io.BytesIO(lines)
        )
        mock_urlopen.return_value.__exit__ = mock.Mock(return_value=False)

        result = hc_main._pull_ollama_model(self.OLLAMA_URL, self.MODEL)

        assert result is True

    @mock.patch("hate_crack.main.urllib.request.urlopen")
    def test_pull_request_payload(self, mock_urlopen):
        """Verify the pull request sends the correct model name and stream=True."""
        mock_urlopen.return_value.__enter__ = mock.Mock(
            return_value=self._make_stream_response(["success"])
        )
        mock_urlopen.return_value.__exit__ = mock.Mock(return_value=False)

        hc_main._pull_ollama_model(self.OLLAMA_URL, self.MODEL)

        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        body = json.loads(req.data.decode("utf-8"))
        assert body["name"] == self.MODEL
        assert body["stream"] is True
        assert req.full_url == f"{self.OLLAMA_URL}/api/pull"


# ---------------------------------------------------------------------------
# hcatOllama 404-retry integration tests
# ---------------------------------------------------------------------------

class TestHcatOllama404Retry:
    """Test that hcatOllama auto-pulls on 404 and retries the generate call."""

    OLLAMA_URL = "http://localhost:11434"
    MODEL = "llama3.2"

    def _generate_response(self, passwords):
        body = json.dumps({"response": "\n".join(passwords)}).encode()
        return io.BytesIO(body)

    def _setup_env(self, tmp_path):
        """Create the files/dirs hcatOllama needs before it hits the API."""
        hash_file = str(tmp_path / "hashes.txt")
        open(hash_file, "w").close()

        # Create a small wordlist for "wordlist" mode
        wordlist = str(tmp_path / "sample.txt")
        with open(wordlist, "w") as f:
            f.write("password\n123456\nletmein\n")

        return hash_file, wordlist

    @mock.patch("hate_crack.main._pull_ollama_model")
    @mock.patch("hate_crack.main.urllib.request.urlopen")
    def test_404_triggers_pull_then_retries(self, mock_urlopen, mock_pull, capsys, tmp_path):
        """A 404 on generate should trigger a pull, then retry successfully."""
        hash_file, wordlist = self._setup_env(tmp_path)

        # First call: 404, second call: success
        generate_ok = mock.MagicMock()
        generate_ok.__enter__ = mock.Mock(
            return_value=self._generate_response(["Password1", "Summer2024"])
        )
        generate_ok.__exit__ = mock.Mock(return_value=False)

        mock_urlopen.side_effect = [
            urllib.error.HTTPError(
                url=f"{self.OLLAMA_URL}/api/generate",
                code=404,
                msg="Not Found",
                hdrs=None,
                fp=None,
            ),
            generate_ok,
        ]
        mock_pull.return_value = True

        with mock.patch.object(hc_main, "ollamaUrl", self.OLLAMA_URL), \
             mock.patch.object(hc_main, "ollamaModel", self.MODEL), \
             mock.patch.object(hc_main, "hcatBin", "/usr/bin/hashcat"), \
             mock.patch.object(hc_main, "hcatTuning", ""), \
             mock.patch.object(hc_main, "hate_path", str(tmp_path)), \
             mock.patch("hate_crack.main.generate_session_id", return_value="test_session"), \
             mock.patch("subprocess.Popen") as mock_popen:

            proc = _make_proc()
            mock_popen.return_value = proc

            hc_main.hcatOllama("0", hash_file, "wordlist", wordlist)

        mock_pull.assert_called_once_with(self.OLLAMA_URL, self.MODEL)
        # urlopen called twice: first 404, then retry
        assert mock_urlopen.call_count == 2

    @mock.patch("hate_crack.main._pull_ollama_model")
    @mock.patch("hate_crack.main.urllib.request.urlopen")
    def test_404_pull_fails_aborts(self, mock_urlopen, mock_pull, capsys, tmp_path):
        """If pull fails after 404, hcatOllama should abort gracefully."""
        hash_file, wordlist = self._setup_env(tmp_path)

        mock_urlopen.side_effect = urllib.error.HTTPError(
            url=f"{self.OLLAMA_URL}/api/generate",
            code=404,
            msg="Not Found",
            hdrs=None,
            fp=None,
        )
        mock_pull.return_value = False

        with mock.patch.object(hc_main, "ollamaUrl", self.OLLAMA_URL), \
             mock.patch.object(hc_main, "ollamaModel", self.MODEL), \
             mock.patch.object(hc_main, "hate_path", str(tmp_path)):

            hc_main.hcatOllama("0", hash_file, "wordlist", wordlist)

        captured = capsys.readouterr()
        assert "Could not pull model" in captured.out
        mock_pull.assert_called_once()

    @mock.patch("hate_crack.main.urllib.request.urlopen")
    def test_non_404_http_error_propagates(self, mock_urlopen, capsys, tmp_path):
        """Non-404 HTTP errors should not trigger a pull attempt."""
        hash_file, wordlist = self._setup_env(tmp_path)

        mock_urlopen.side_effect = urllib.error.HTTPError(
            url=f"{self.OLLAMA_URL}/api/generate",
            code=500,
            msg="Internal Server Error",
            hdrs=None,
            fp=None,
        )

        with mock.patch.object(hc_main, "ollamaUrl", self.OLLAMA_URL), \
             mock.patch.object(hc_main, "ollamaModel", self.MODEL), \
             mock.patch.object(hc_main, "hate_path", str(tmp_path)):

            hc_main.hcatOllama("0", hash_file, "wordlist", wordlist)

        captured = capsys.readouterr()
        # HTTPError is a subclass of URLError, so it hits the URLError handler
        assert "Could not connect to Ollama" in captured.out or "Error calling Ollama API" in captured.out
        assert "500" in captured.out


# ---------------------------------------------------------------------------
# Step A: Mode routing, prompt construction, early-return error paths
# ---------------------------------------------------------------------------

class TestHcatOllamaModeRouting:
    """Test mode selection, prompt building, and early-return errors."""

    def test_unknown_mode_prints_error(self, ollama_env, capsys):
        """Bad mode string → error message, no API call."""
        with ollama_globals(ollama_env.tmp_path), \
             mock.patch("hate_crack.main.urllib.request.urlopen") as mock_url:
            hc_main.hcatOllama("0", ollama_env.hash_file, "bogus", "")

        captured = capsys.readouterr()
        assert "Unknown LLM generation mode" in captured.out
        mock_url.assert_not_called()

    def test_missing_wordlist_prints_error(self, ollama_env, capsys):
        """Non-existent wordlist path → error, no API call."""
        with ollama_globals(ollama_env.tmp_path), \
             mock.patch("hate_crack.main.urllib.request.urlopen") as mock_url:
            hc_main.hcatOllama(
                "0", ollama_env.hash_file, "wordlist",
                "/no/such/wordlist.txt",
            )

        captured = capsys.readouterr()
        assert "Wordlist not found" in captured.out
        mock_url.assert_not_called()

    def test_wordlist_mode_reads_all_lines(self, ollama_env, capsys):
        """All non-blank lines from the wordlist should appear in the prompt."""
        # Write 600 lines to the wordlist
        big_wordlist = ollama_env.tmp_path / "big.txt"
        big_wordlist.write_text("\n".join(f"pass{i}" for i in range(600)) + "\n")

        captured_payload = {}

        def fake_urlopen(req, **kwargs):
            captured_payload["data"] = json.loads(req.data.decode())
            return _generate_response(["Password1"])

        with ollama_globals(ollama_env.tmp_path), \
             mock.patch("hate_crack.main.urllib.request.urlopen", side_effect=fake_urlopen), \
             mock.patch("subprocess.Popen") as mock_popen:
            proc = _make_proc()
            mock_popen.return_value = proc
            hc_main.hcatOllama(
                "0", ollama_env.hash_file, "wordlist", str(big_wordlist),
            )

        prompt_text = captured_payload["data"]["prompt"]
        # All lines should be included in the prompt
        assert "pass0" in prompt_text
        assert "pass499" in prompt_text
        assert "pass599" in prompt_text

    def test_target_mode_includes_context_in_prompt(self, ollama_env, capsys):
        """Company, industry, and location should appear in the prompt."""
        captured_payload = {}

        def fake_urlopen(req, **kwargs):
            captured_payload["data"] = json.loads(req.data.decode())
            return _generate_response(["AcmeCorp2024"])

        target_info = {
            "company": "AcmeCorp",
            "industry": "Finance",
            "location": "New York",
        }
        with ollama_globals(ollama_env.tmp_path), \
             mock.patch("hate_crack.main.urllib.request.urlopen", side_effect=fake_urlopen), \
             mock.patch("subprocess.Popen") as mock_popen:
            proc = _make_proc()
            mock_popen.return_value = proc
            hc_main.hcatOllama(
                "0", ollama_env.hash_file, "target", target_info,
            )

        prompt_text = captured_payload["data"]["prompt"]
        assert "AcmeCorp" in prompt_text
        assert "Finance" in prompt_text
        assert "New York" in prompt_text


# ---------------------------------------------------------------------------
# Step B: Candidate filtering / post-processing
# ---------------------------------------------------------------------------

class TestHcatOllamaCandidateFiltering:
    """Test regex stripping, blank-line removal, 128-char limit, empty-result handling."""

    def _run_with_response(self, ollama_env, response_text):
        """Run hcatOllama with a canned Ollama response_text, return candidates file content."""
        body = json.dumps({"response": response_text}).encode()
        resp = mock.MagicMock()
        resp.__enter__ = mock.Mock(return_value=io.BytesIO(body))
        resp.__exit__ = mock.Mock(return_value=False)

        candidates_path = f"{ollama_env.hash_file}.ollama_candidates"
        captured = {}

        def capture_popen(cmd, **kwargs):
            # Read the candidates file before hashcat "runs" (cleanup happens after)
            if os.path.isfile(candidates_path):
                with open(candidates_path) as f:
                    captured["content"] = f.read()
            return _make_proc()

        with ollama_globals(ollama_env.tmp_path), \
             mock.patch("hate_crack.main.urllib.request.urlopen", return_value=resp), \
             mock.patch("subprocess.Popen", side_effect=capture_popen):
            hc_main.hcatOllama(
                "0", ollama_env.hash_file, "wordlist", ollama_env.wordlist,
            )

        return captured.get("content")

    def test_strips_numeric_dot_prefix(self, ollama_env):
        content = self._run_with_response(ollama_env, "1. Password1\n2. Summer2024")
        assert content is not None
        lines = [l for l in content.strip().split("\n") if l]
        assert "Password1" in lines
        assert "Summer2024" in lines
        # No line should start with a digit+dot
        for line in lines:
            assert not line.startswith("1.")
            assert not line.startswith("2.")

    def test_strips_dash_and_asterisk_prefix(self, ollama_env):
        content = self._run_with_response(ollama_env, "- foo\n* bar")
        assert content is not None
        lines = [l for l in content.strip().split("\n") if l]
        assert "foo" in lines
        assert "bar" in lines

    def test_skips_blank_lines(self, ollama_env):
        content = self._run_with_response(ollama_env, "alpha\n\n\nbeta\n\n")
        assert content is not None
        lines = [l for l in content.strip().split("\n") if l]
        assert lines == ["alpha", "beta"]

    def test_rejects_over_128_chars(self, ollama_env):
        long_pw = "A" * 129
        content = self._run_with_response(ollama_env, f"short\n{long_pw}\nkeep")
        assert content is not None
        lines = [l for l in content.strip().split("\n") if l]
        assert "short" in lines
        assert "keep" in lines
        assert long_pw not in lines

    def test_accepts_exactly_128_chars(self, ollama_env):
        exact_pw = "B" * 128
        content = self._run_with_response(ollama_env, f"{exact_pw}\nother")
        assert content is not None
        lines = [l for l in content.strip().split("\n") if l]
        assert exact_pw in lines

    def test_empty_response_prints_error(self, ollama_env, capsys):
        self._run_with_response(ollama_env, "")
        captured = capsys.readouterr()
        assert "no usable" in captured.out.lower()

    def test_missing_response_key(self, ollama_env, capsys):
        """If the JSON has no 'response' key, treat as empty."""
        body = json.dumps({"other": "stuff"}).encode()
        resp = mock.MagicMock()
        resp.__enter__ = mock.Mock(return_value=io.BytesIO(body))
        resp.__exit__ = mock.Mock(return_value=False)

        with ollama_globals(ollama_env.tmp_path), \
             mock.patch("hate_crack.main.urllib.request.urlopen", return_value=resp):
            hc_main.hcatOllama(
                "0", ollama_env.hash_file, "wordlist", ollama_env.wordlist,
            )

        captured = capsys.readouterr()
        assert "no usable" in captured.out.lower()


# ---------------------------------------------------------------------------
# Step B: API error paths (non-404)
# ---------------------------------------------------------------------------

class TestHcatOllamaApiErrors:
    """Test connection errors and generic exceptions during the generate call."""

    def test_url_error_prints_connection_error(self, ollama_env, capsys):
        with ollama_globals(ollama_env.tmp_path), \
             mock.patch(
                 "hate_crack.main.urllib.request.urlopen",
                 side_effect=urllib.error.URLError("Connection refused"),
             ):
            hc_main.hcatOllama(
                "0", ollama_env.hash_file, "wordlist", ollama_env.wordlist,
            )

        captured = capsys.readouterr()
        assert "Could not connect" in captured.out
        assert "Ensure Ollama is running" in captured.out

    def test_generic_exception_prints_error(self, ollama_env, capsys):
        with ollama_globals(ollama_env.tmp_path), \
             mock.patch(
                 "hate_crack.main.urllib.request.urlopen",
                 side_effect=RuntimeError("boom"),
             ):
            hc_main.hcatOllama(
                "0", ollama_env.hash_file, "wordlist", ollama_env.wordlist,
            )

        captured = capsys.readouterr()
        assert "Error calling Ollama API" in captured.out

    def test_generate_request_payload(self, ollama_env):
        """Verify the /api/generate request has correct URL, model, stream=false."""
        captured_req = {}

        def fake_urlopen(req, **kwargs):
            captured_req["url"] = req.full_url
            captured_req["body"] = json.loads(req.data.decode())
            return _generate_response(["Password1"])

        with ollama_globals(ollama_env.tmp_path), \
             mock.patch("hate_crack.main.urllib.request.urlopen", side_effect=fake_urlopen), \
             mock.patch("subprocess.Popen") as mock_popen:
            proc = _make_proc()
            mock_popen.return_value = proc
            hc_main.hcatOllama(
                "0", ollama_env.hash_file, "wordlist", ollama_env.wordlist,
            )

        assert captured_req["url"] == f"{OLLAMA_URL}/api/generate"
        assert captured_req["body"]["model"] == MODEL
        assert captured_req["body"]["stream"] is False
        assert len(captured_req["body"]["prompt"]) > 0


# ---------------------------------------------------------------------------
# Step C: Hashcat command construction
# ---------------------------------------------------------------------------

class TestHcatOllamaHashcatCommand:
    """Test hashcat command flags and process handling."""

    def _run_full(self, ollama_env, tuning="", potfile=""):
        """Run hcatOllama through all steps, returning the list of Popen calls."""
        popen_calls = []

        def track_popen(cmd, **kwargs):
            popen_calls.append((list(cmd), dict(kwargs)))
            return _make_proc()

        with ollama_globals(ollama_env.tmp_path, tuning=tuning, potfile=potfile), \
             _urlopen_with_response(["Password1"]), \
             mock.patch("subprocess.Popen", side_effect=track_popen), \
             mock.patch("hate_crack.main.generate_session_id", return_value="test_session"):
            hc_main.hcatOllama(
                "1000", ollama_env.hash_file, "wordlist", ollama_env.wordlist,
            )

        return popen_calls

    def test_hashcat_command_structure(self, ollama_env):
        """First Popen call should be a straight wordlist attack with candidates file,
        followed by rule-based attacks."""
        calls = self._run_full(ollama_env)
        assert len(calls) >= 1, "Expected at least one Popen call (hashcat)"

        # First call: base wordlist attack (no rules)
        hashcat_cmd = calls[0][0]
        assert hashcat_cmd[0] == "/usr/bin/hashcat"
        assert "-m" in hashcat_cmd
        m_idx = hashcat_cmd.index("-m")
        assert hashcat_cmd[m_idx + 1] == "1000"
        # Should use the candidates wordlist file
        candidates_path = f"{ollama_env.hash_file}.ollama_candidates"
        assert candidates_path in hashcat_cmd
        # First call should NOT have mask attack flags
        assert "-a" not in hashcat_cmd
        assert "--markov-hcstat2" not in " ".join(hashcat_cmd)
        assert "--increment" not in hashcat_cmd
        # First call should NOT have -r (rule) flag
        assert "-r" not in hashcat_cmd

        # Subsequent calls: rule-based attacks
        if len(calls) > 1:
            for rule_cmd, _ in calls[1:]:
                assert "-r" in rule_cmd
                assert candidates_path in rule_cmd

    def test_hashcat_includes_tuning(self, ollama_env):
        """-w 3 tuning flag should be appended to hashcat cmd."""
        calls = self._run_full(ollama_env, tuning="-w 3")
        hashcat_cmd = calls[0][0]
        assert "-w" in hashcat_cmd
        w_idx = hashcat_cmd.index("-w")
        assert hashcat_cmd[w_idx + 1] == "3"

    def test_hashcat_includes_potfile(self, ollama_env):
        """--potfile-path should be present when hcatPotfilePath is set."""
        calls = self._run_full(ollama_env, potfile="/tmp/test.potfile")
        hashcat_cmd = calls[0][0]
        potfile_flags = [f for f in hashcat_cmd if "--potfile-path=" in f]
        assert len(potfile_flags) == 1
        assert potfile_flags[0] == "--potfile-path=/tmp/test.potfile"

    def test_hashcat_keyboard_interrupt(self, ollama_env, capsys):
        """KeyboardInterrupt during hashcat should kill the process."""
        proc = mock.MagicMock()
        proc.pid = 99999
        proc.wait.side_effect = KeyboardInterrupt()

        with ollama_globals(ollama_env.tmp_path), \
             _urlopen_with_response(["Password1"]), \
             mock.patch("subprocess.Popen", return_value=proc), \
             mock.patch("hate_crack.main.generate_session_id", return_value="test_session"):
            hc_main.hcatOllama(
                "0", ollama_env.hash_file, "wordlist", ollama_env.wordlist,
            )

        captured = capsys.readouterr()
        assert "Killing PID" in captured.out
        proc.kill.assert_called_once()


# ---------------------------------------------------------------------------
# Step F: Cleanup
# ---------------------------------------------------------------------------

class TestHcatOllamaWordlistPersistence:
    """Test that the generated wordlist file persists after the run."""

    def test_candidates_file_persists(self, ollama_env):
        """ollama_candidates wordlist should remain after the run."""
        with ollama_globals(ollama_env.tmp_path), \
             _urlopen_with_response(["Password1"]), \
             mock.patch("subprocess.Popen", return_value=_make_proc()), \
             mock.patch("hate_crack.main.generate_session_id", return_value="test_session"):
            hc_main.hcatOllama(
                "0", ollama_env.hash_file, "wordlist", ollama_env.wordlist,
            )

        candidates_path = f"{ollama_env.hash_file}.ollama_candidates"
        assert os.path.isfile(candidates_path), "candidates wordlist should persist"


# ---------------------------------------------------------------------------
# attacks.py: ollama_attack() UI handler
# ---------------------------------------------------------------------------

class TestOllamaAttackHandler:
    """Test the ollama_attack(ctx) menu handler in attacks.py."""

    def _make_ctx(self, **overrides):
        """Build a mock ctx with the attributes ollama_attack() reads."""
        ctx = mock.MagicMock()
        ctx.hcatHashType = "0"
        ctx.hcatHashFile = "/tmp/hashes.txt"
        ctx.hcatWordlists = "/tmp/wordlists"
        for k, v in overrides.items():
            setattr(ctx, k, v)
        return ctx

    def test_target_mode(self):
        """ollama_attack prompts for company/industry/location and calls hcatOllama."""
        from hate_crack.attacks import ollama_attack

        ctx = self._make_ctx()
        with mock.patch("builtins.input", side_effect=["AcmeCorp", "Finance", "NYC"]):
            ollama_attack(ctx)

        ctx.hcatOllama.assert_called_once()
        call_args = ctx.hcatOllama.call_args
        assert call_args[0][2] == "target"
        target_info = call_args[0][3]
        assert target_info["company"] == "AcmeCorp"
        assert target_info["industry"] == "Finance"
        assert target_info["location"] == "NYC"

