"""Unit tests for _pull_ollama_model helper, hcatMarkov steps A-F, and markov_attack handler."""

import io
import json
import lzma
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
def markov_env(tmp_path):
    """Create the filesystem layout hcatMarkov expects."""
    hash_file = tmp_path / "hashes.txt"
    hash_file.touch()

    hcutil_bin = tmp_path / "hashcat-utils" / "bin"
    hcutil_bin.mkdir(parents=True)
    hcstat2gen = hcutil_bin / hc_main.hcatHcstat2genBin
    hcstat2gen.touch()

    wordlist = tmp_path / "sample.txt"
    wordlist.write_text("password\n123456\nletmein\n")

    return SimpleNamespace(
        tmp_path=tmp_path,
        hash_file=str(hash_file),
        hcstat2gen=str(hcstat2gen),
        wordlist=str(wordlist),
    )


@contextmanager
def markov_globals(tmp_path, tuning="", potfile=""):
    """Patch the hc_main globals that hcatMarkov reads."""
    with mock.patch.object(hc_main, "ollamaUrl", OLLAMA_URL), \
         mock.patch.object(hc_main, "ollamaModel", MODEL), \
         mock.patch.object(hc_main, "hcatBin", "/usr/bin/hashcat"), \
         mock.patch.object(hc_main, "hcatTuning", tuning), \
         mock.patch.object(hc_main, "hcatPotfilePath", potfile), \
         mock.patch.object(hc_main, "hate_path", str(tmp_path)):
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
# hcatMarkov 404-retry integration tests
# ---------------------------------------------------------------------------

class TestHcatMarkov404Retry:
    """Test that hcatMarkov auto-pulls on 404 and retries the generate call."""

    OLLAMA_URL = "http://localhost:11434"
    MODEL = "llama3.2"

    def _generate_response(self, passwords):
        body = json.dumps({"response": "\n".join(passwords)}).encode()
        return io.BytesIO(body)

    def _setup_env(self, tmp_path):
        """Create the files/dirs hcatMarkov needs before it hits the API."""
        hash_file = str(tmp_path / "hashes.txt")
        open(hash_file, "w").close()

        # hcatMarkov checks for hcstat2gen binary at startup
        hcutil_bin = tmp_path / "hashcat-utils" / "bin"
        hcutil_bin.mkdir(parents=True, exist_ok=True)
        hcstat2gen = hcutil_bin / hc_main.hcatHcstat2genBin
        hcstat2gen.touch()

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
             mock.patch("subprocess.Popen") as mock_popen:

            proc = _make_proc()
            mock_popen.return_value = proc

            hc_main.hcatMarkov("0", hash_file, "wordlist", wordlist, 10)

        mock_pull.assert_called_once_with(self.OLLAMA_URL, self.MODEL)
        # urlopen called twice: first 404, then retry
        assert mock_urlopen.call_count == 2

    @mock.patch("hate_crack.main._pull_ollama_model")
    @mock.patch("hate_crack.main.urllib.request.urlopen")
    def test_404_pull_fails_aborts(self, mock_urlopen, mock_pull, capsys, tmp_path):
        """If pull fails after 404, hcatMarkov should abort gracefully."""
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

            hc_main.hcatMarkov("0", hash_file, "wordlist", wordlist, 10)

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

            hc_main.hcatMarkov("0", hash_file, "wordlist", wordlist, 10)

        captured = capsys.readouterr()
        # HTTPError is a subclass of URLError, so it hits the URLError handler
        assert "Could not connect to Ollama" in captured.out or "Error calling Ollama API" in captured.out
        assert "500" in captured.out


# ---------------------------------------------------------------------------
# Step A: Mode routing, prompt construction, early-return error paths
# ---------------------------------------------------------------------------

class TestHcatMarkovModeRouting:
    """Test mode selection, prompt building, and early-return errors."""

    def test_unknown_mode_prints_error(self, markov_env, capsys):
        """Bad mode string → error message, no API call."""
        with markov_globals(markov_env.tmp_path), \
             mock.patch("hate_crack.main.urllib.request.urlopen") as mock_url:
            hc_main.hcatMarkov("0", markov_env.hash_file, "bogus", "", 10)

        captured = capsys.readouterr()
        assert "Unknown Markov generation mode" in captured.out
        mock_url.assert_not_called()

    def test_missing_wordlist_prints_error(self, markov_env, capsys):
        """Non-existent wordlist path → error, no API call."""
        with markov_globals(markov_env.tmp_path), \
             mock.patch("hate_crack.main.urllib.request.urlopen") as mock_url:
            hc_main.hcatMarkov(
                "0", markov_env.hash_file, "wordlist",
                "/no/such/wordlist.txt", 10,
            )

        captured = capsys.readouterr()
        assert "Wordlist not found" in captured.out
        mock_url.assert_not_called()

    def test_missing_hcstat2gen_prints_error(self, tmp_path, capsys):
        """No hcstat2gen binary → error, no API call."""
        hash_file = tmp_path / "hashes.txt"
        hash_file.touch()
        wordlist = tmp_path / "sample.txt"
        wordlist.write_text("password\n")

        with markov_globals(tmp_path), \
             mock.patch("hate_crack.main.urllib.request.urlopen") as mock_url:
            hc_main.hcatMarkov("0", str(hash_file), "wordlist", str(wordlist), 10)

        captured = capsys.readouterr()
        assert "hcstat2gen not found" in captured.out
        mock_url.assert_not_called()

    def test_wordlist_mode_reads_up_to_500_lines(self, markov_env, capsys):
        """Only the first 500 non-blank lines should appear in the prompt payload."""
        # Write 600 lines to the wordlist
        big_wordlist = markov_env.tmp_path / "big.txt"
        big_wordlist.write_text("\n".join(f"pass{i}" for i in range(600)) + "\n")

        captured_payload = {}

        def fake_urlopen(req, **kwargs):
            captured_payload["data"] = json.loads(req.data.decode())
            return _generate_response(["Password1"])

        with markov_globals(markov_env.tmp_path), \
             mock.patch("hate_crack.main.urllib.request.urlopen", side_effect=fake_urlopen), \
             mock.patch("subprocess.Popen") as mock_popen:
            proc = _make_proc()
            mock_popen.return_value = proc
            hc_main.hcatMarkov(
                "0", markov_env.hash_file, "wordlist", str(big_wordlist), 10,
            )

        prompt_text = captured_payload["data"]["prompt"]
        # Should contain pass0 through pass499 but NOT pass500+
        assert "pass499" in prompt_text
        assert "pass500" not in prompt_text

    def test_target_mode_includes_context_in_prompt(self, markov_env, capsys):
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
        with markov_globals(markov_env.tmp_path), \
             mock.patch("hate_crack.main.urllib.request.urlopen", side_effect=fake_urlopen), \
             mock.patch("subprocess.Popen") as mock_popen:
            proc = _make_proc()
            mock_popen.return_value = proc
            hc_main.hcatMarkov(
                "0", markov_env.hash_file, "target", target_info, 10,
            )

        prompt_text = captured_payload["data"]["prompt"]
        assert "AcmeCorp" in prompt_text
        assert "Finance" in prompt_text
        assert "New York" in prompt_text


# ---------------------------------------------------------------------------
# Step B: Candidate filtering / post-processing
# ---------------------------------------------------------------------------

class TestHcatMarkovCandidateFiltering:
    """Test regex stripping, blank-line removal, 128-char limit, empty-result handling."""

    def _run_with_response(self, markov_env, response_text):
        """Run hcatMarkov with a canned Ollama response_text, return candidates file content."""
        body = json.dumps({"response": response_text}).encode()
        resp = mock.MagicMock()
        resp.__enter__ = mock.Mock(return_value=io.BytesIO(body))
        resp.__exit__ = mock.Mock(return_value=False)

        with markov_globals(markov_env.tmp_path), \
             mock.patch("hate_crack.main.urllib.request.urlopen", return_value=resp), \
             mock.patch("subprocess.Popen") as mock_popen:
            proc = _make_proc()
            mock_popen.return_value = proc
            hc_main.hcatMarkov(
                "0", markov_env.hash_file, "wordlist", markov_env.wordlist, 10,
            )

        candidates_path = f"{markov_env.hash_file}.markov_candidates"
        if os.path.isfile(candidates_path):
            with open(candidates_path) as f:
                return f.read()
        return None

    def test_strips_numeric_dot_prefix(self, markov_env):
        content = self._run_with_response(markov_env, "1. Password1\n2. Summer2024")
        assert content is not None
        lines = [l for l in content.strip().split("\n") if l]
        assert "Password1" in lines
        assert "Summer2024" in lines
        # No line should start with a digit+dot
        for line in lines:
            assert not line.startswith("1.")
            assert not line.startswith("2.")

    def test_strips_dash_and_asterisk_prefix(self, markov_env):
        content = self._run_with_response(markov_env, "- foo\n* bar")
        assert content is not None
        lines = [l for l in content.strip().split("\n") if l]
        assert "foo" in lines
        assert "bar" in lines

    def test_skips_blank_lines(self, markov_env):
        content = self._run_with_response(markov_env, "alpha\n\n\nbeta\n\n")
        assert content is not None
        lines = [l for l in content.strip().split("\n") if l]
        assert lines == ["alpha", "beta"]

    def test_rejects_over_128_chars(self, markov_env):
        long_pw = "A" * 129
        content = self._run_with_response(markov_env, f"short\n{long_pw}\nkeep")
        assert content is not None
        lines = [l for l in content.strip().split("\n") if l]
        assert "short" in lines
        assert "keep" in lines
        assert long_pw not in lines

    def test_accepts_exactly_128_chars(self, markov_env):
        exact_pw = "B" * 128
        content = self._run_with_response(markov_env, f"{exact_pw}\nother")
        assert content is not None
        lines = [l for l in content.strip().split("\n") if l]
        assert exact_pw in lines

    def test_empty_response_prints_error(self, markov_env, capsys):
        self._run_with_response(markov_env, "")
        captured = capsys.readouterr()
        assert "no usable" in captured.out.lower()

    def test_missing_response_key(self, markov_env, capsys):
        """If the JSON has no 'response' key, treat as empty."""
        body = json.dumps({"other": "stuff"}).encode()
        resp = mock.MagicMock()
        resp.__enter__ = mock.Mock(return_value=io.BytesIO(body))
        resp.__exit__ = mock.Mock(return_value=False)

        with markov_globals(markov_env.tmp_path), \
             mock.patch("hate_crack.main.urllib.request.urlopen", return_value=resp):
            hc_main.hcatMarkov(
                "0", markov_env.hash_file, "wordlist", markov_env.wordlist, 10,
            )

        captured = capsys.readouterr()
        assert "no usable" in captured.out.lower()


# ---------------------------------------------------------------------------
# Step B: API error paths (non-404)
# ---------------------------------------------------------------------------

class TestHcatMarkovApiErrors:
    """Test connection errors and generic exceptions during the generate call."""

    def test_url_error_prints_connection_error(self, markov_env, capsys):
        with markov_globals(markov_env.tmp_path), \
             mock.patch(
                 "hate_crack.main.urllib.request.urlopen",
                 side_effect=urllib.error.URLError("Connection refused"),
             ):
            hc_main.hcatMarkov(
                "0", markov_env.hash_file, "wordlist", markov_env.wordlist, 10,
            )

        captured = capsys.readouterr()
        assert "Could not connect" in captured.out
        assert "Ensure Ollama is running" in captured.out

    def test_generic_exception_prints_error(self, markov_env, capsys):
        with markov_globals(markov_env.tmp_path), \
             mock.patch(
                 "hate_crack.main.urllib.request.urlopen",
                 side_effect=RuntimeError("boom"),
             ):
            hc_main.hcatMarkov(
                "0", markov_env.hash_file, "wordlist", markov_env.wordlist, 10,
            )

        captured = capsys.readouterr()
        assert "Error calling Ollama API" in captured.out

    def test_generate_request_payload(self, markov_env):
        """Verify the /api/generate request has correct URL, model, stream=false."""
        captured_req = {}

        def fake_urlopen(req, **kwargs):
            captured_req["url"] = req.full_url
            captured_req["body"] = json.loads(req.data.decode())
            return _generate_response(["Password1"])

        with markov_globals(markov_env.tmp_path), \
             mock.patch("hate_crack.main.urllib.request.urlopen", side_effect=fake_urlopen), \
             mock.patch("subprocess.Popen") as mock_popen:
            proc = _make_proc()
            mock_popen.return_value = proc
            hc_main.hcatMarkov(
                "0", markov_env.hash_file, "wordlist", markov_env.wordlist, 10,
            )

        assert captured_req["url"] == f"{OLLAMA_URL}/api/generate"
        assert captured_req["body"]["model"] == MODEL
        assert captured_req["body"]["stream"] is False
        assert len(captured_req["body"]["prompt"]) > 0


# ---------------------------------------------------------------------------
# Steps C + D: hcstat2gen execution and LZMA compression
# ---------------------------------------------------------------------------

class TestHcatMarkovHcstat2gen:
    """Test hcstat2gen subprocess step."""

    def test_hcstat2gen_correct_args(self, markov_env):
        """hcstat2gen should be called with [binary_path, raw_output_path] and stdin=file."""
        hcstat2_raw_path = f"{markov_env.hash_file}.hcstat2_raw"
        hcstat2gen_path = markov_env.hcstat2gen

        call_args_list = []

        def track_popen(cmd, **kwargs):
            call_args_list.append((list(cmd), dict(kwargs)))
            proc = _make_proc()
            # Create raw hcstat2 file so the LZMA compression step continues
            if cmd[0] == hcstat2gen_path:
                with open(hcstat2_raw_path, "wb") as f:
                    f.write(b"\x00" * 100)
            return proc

        with markov_globals(markov_env.tmp_path), \
             _urlopen_with_response(["Password1"]), \
             mock.patch("subprocess.Popen", side_effect=track_popen), \
             mock.patch("hate_crack.main.generate_session_id", return_value="test_session"):
            hc_main.hcatMarkov(
                "0", markov_env.hash_file, "wordlist", markov_env.wordlist, 10,
            )

        # First Popen call should be hcstat2gen writing to the raw path
        first_cmd, first_kwargs = call_args_list[0]
        assert first_cmd[0] == hcstat2gen_path
        assert first_cmd[1] == hcstat2_raw_path
        assert "stdin" in first_kwargs

    def test_hcstat2gen_keyboard_interrupt(self, markov_env, capsys):
        """KeyboardInterrupt during hcstat2gen should kill the process and return."""
        proc = mock.MagicMock()
        proc.communicate.side_effect = KeyboardInterrupt()
        proc.pid = 12345

        with markov_globals(markov_env.tmp_path), \
             _urlopen_with_response(["Password1"]), \
             mock.patch("subprocess.Popen", return_value=proc):
            hc_main.hcatMarkov(
                "0", markov_env.hash_file, "wordlist", markov_env.wordlist, 10,
            )

        captured = capsys.readouterr()
        assert "Killing PID" in captured.out
        proc.kill.assert_called_once()

    def test_hcstat2gen_no_output_file(self, markov_env, capsys):
        """If hcstat2gen doesn't produce a raw output file, abort with error."""
        proc = mock.MagicMock()
        proc.communicate.return_value = (b"", b"")
        proc.returncode = 0
        # Don't create hcstat2_raw_path → triggers the "did not produce" error

        with markov_globals(markov_env.tmp_path), \
             _urlopen_with_response(["Password1"]), \
             mock.patch("subprocess.Popen", return_value=proc):
            hc_main.hcatMarkov(
                "0", markov_env.hash_file, "wordlist", markov_env.wordlist, 10,
            )

        captured = capsys.readouterr()
        assert "did not produce output file" in captured.out

    def test_lzma_compression_error(self, markov_env, capsys):
        """LZMAError during compression → error message, no hashcat run."""
        hcstat2_raw_path = f"{markov_env.hash_file}.hcstat2_raw"

        def track_popen(cmd, **kwargs):
            proc = _make_proc()
            if cmd[0] == markov_env.hcstat2gen:
                with open(hcstat2_raw_path, "wb") as f:
                    f.write(b"\x00" * 100)
            return proc

        with markov_globals(markov_env.tmp_path), \
             _urlopen_with_response(["Password1"]), \
             mock.patch("subprocess.Popen", side_effect=track_popen) as mock_popen, \
             mock.patch("hate_crack.main.lzma.compress", side_effect=lzma.LZMAError("bad data")):
            hc_main.hcatMarkov(
                "0", markov_env.hash_file, "wordlist", markov_env.wordlist, 10,
            )

        captured = capsys.readouterr()
        assert "Error compressing" in captured.out
        # Should only have 1 Popen call (hcstat2gen), NOT a second for hashcat
        assert mock_popen.call_count == 1



# ---------------------------------------------------------------------------
# Step E: Hashcat command construction
# ---------------------------------------------------------------------------

class TestHcatMarkovHashcatCommand:
    """Test hashcat command flags and process handling."""

    def _run_full(self, markov_env, tuning="", potfile=""):
        """Run hcatMarkov through all steps, returning the list of Popen calls."""
        hcstat2_raw_path = f"{markov_env.hash_file}.hcstat2_raw"
        popen_calls = []

        def track_popen(cmd, **kwargs):
            popen_calls.append((list(cmd), dict(kwargs)))
            proc = _make_proc()
            # hcstat2gen: create the raw output file (LZMA2 compression step will follow)
            if cmd[0] == markov_env.hcstat2gen:
                with open(hcstat2_raw_path, "wb") as f:
                    f.write(b"\x00" * 100)
            return proc

        with markov_globals(markov_env.tmp_path, tuning=tuning, potfile=potfile), \
             _urlopen_with_response(["Password1"]), \
             mock.patch("subprocess.Popen", side_effect=track_popen), \
             mock.patch("hate_crack.main.generate_session_id", return_value="test_session"):
            hc_main.hcatMarkov(
                "1000", markov_env.hash_file, "wordlist", markov_env.wordlist, 10,
            )

        return popen_calls

    def test_hashcat_command_structure(self, markov_env):
        """Hashcat cmd should include -m, -a 3, --markov-hcstat2, --increment, mask."""
        calls = self._run_full(markov_env)
        assert len(calls) >= 2, "Expected at least hcstat2gen + hashcat Popen calls"

        hashcat_cmd = calls[1][0]
        assert hashcat_cmd[0] == "/usr/bin/hashcat"
        assert "-m" in hashcat_cmd
        m_idx = hashcat_cmd.index("-m")
        assert hashcat_cmd[m_idx + 1] == "1000"
        assert "-a" in hashcat_cmd
        a_idx = hashcat_cmd.index("-a")
        assert hashcat_cmd[a_idx + 1] == "3"
        # Check markov hcstat2 flag
        hcstat2_flags = [f for f in hashcat_cmd if "--markov-hcstat2=" in f]
        assert len(hcstat2_flags) == 1
        assert hcstat2_flags[0].endswith(".hcstat2")
        assert "--increment" in hashcat_cmd
        # Mask should be the last positional arg
        assert "?a?a?a?a?a?a?a?a?a?a?a?a?a?a" in hashcat_cmd

    def test_hashcat_includes_tuning(self, markov_env):
        """-w 3 tuning flag should be appended to hashcat cmd."""
        calls = self._run_full(markov_env, tuning="-w 3")
        hashcat_cmd = calls[1][0]
        assert "-w" in hashcat_cmd
        w_idx = hashcat_cmd.index("-w")
        assert hashcat_cmd[w_idx + 1] == "3"

    def test_hashcat_includes_potfile(self, markov_env):
        """--potfile-path should be present when hcatPotfilePath is set."""
        calls = self._run_full(markov_env, potfile="/tmp/test.potfile")
        hashcat_cmd = calls[1][0]
        potfile_flags = [f for f in hashcat_cmd if "--potfile-path=" in f]
        assert len(potfile_flags) == 1
        assert potfile_flags[0] == "--potfile-path=/tmp/test.potfile"

    def test_hashcat_keyboard_interrupt(self, markov_env, capsys):
        """KeyboardInterrupt during hashcat should kill the process."""
        hcstat2_raw_path = f"{markov_env.hash_file}.hcstat2_raw"
        call_count = [0]

        def track_popen(cmd, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                # hcstat2gen: succeeds and creates raw file
                proc = _make_proc()
                proc.pid = 99999
                with open(hcstat2_raw_path, "wb") as f:
                    f.write(b"\x00" * 100)
            else:
                # hashcat: KeyboardInterrupt
                proc = mock.MagicMock()
                proc.pid = 99999
                proc.wait.side_effect = KeyboardInterrupt()
            return proc

        with markov_globals(markov_env.tmp_path), \
             _urlopen_with_response(["Password1"]), \
             mock.patch("subprocess.Popen", side_effect=track_popen), \
             mock.patch("hate_crack.main.generate_session_id", return_value="test_session"):
            hc_main.hcatMarkov(
                "0", markov_env.hash_file, "wordlist", markov_env.wordlist, 10,
            )

        captured = capsys.readouterr()
        assert "Killing PID" in captured.out


# ---------------------------------------------------------------------------
# Step F: Cleanup
# ---------------------------------------------------------------------------

class TestHcatMarkovCleanup:
    """Test that temp files are removed after a successful run."""

    def _run_full(self, markov_env):
        """Run hcatMarkov through all steps successfully."""
        hcstat2_raw_path = f"{markov_env.hash_file}.hcstat2_raw"

        def track_popen(cmd, **kwargs):
            proc = _make_proc()
            if cmd[0] == markov_env.hcstat2gen:
                with open(hcstat2_raw_path, "wb") as f:
                    f.write(b"\x00" * 100)
            return proc

        with markov_globals(markov_env.tmp_path), \
             _urlopen_with_response(["Password1"]), \
             mock.patch("subprocess.Popen", side_effect=track_popen), \
             mock.patch("hate_crack.main.generate_session_id", return_value="test_session"):
            hc_main.hcatMarkov(
                "0", markov_env.hash_file, "wordlist", markov_env.wordlist, 10,
            )

    def test_temp_files_removed(self, markov_env):
        """markov_candidates and hcstat2_raw should be deleted; hcstat2 should remain."""
        self._run_full(markov_env)

        candidates_path = f"{markov_env.hash_file}.markov_candidates"
        hcstat2_raw_path = f"{markov_env.hash_file}.hcstat2_raw"
        hcstat2_path = f"{markov_env.hash_file}.hcstat2"

        assert not os.path.exists(candidates_path), "candidates temp file should be removed"
        assert not os.path.exists(hcstat2_raw_path), "raw hcstat2 temp file should be removed"
        assert os.path.isfile(hcstat2_path), "compressed hcstat2 file should remain"

    def test_cleanup_ignores_missing_files(self, markov_env):
        """No exception if temp files are already gone before cleanup."""
        # This just verifies the run completes without error even though
        # we don't interfere with normal cleanup
        self._run_full(markov_env)  # should not raise


# ---------------------------------------------------------------------------
# attacks.py: markov_attack() UI handler
# ---------------------------------------------------------------------------

class TestMarkovAttackHandler:
    """Test the markov_attack(ctx) menu handler in attacks.py."""

    def _make_ctx(self, **overrides):
        """Build a mock ctx with the attributes markov_attack() reads."""
        ctx = mock.MagicMock()
        ctx.hcatHashType = "0"
        ctx.hcatHashFile = "/tmp/hashes.txt"
        ctx.markovWordlist = "/tmp/wordlist.txt"
        ctx.markovCandidateCount = 5000
        ctx.hcatWordlists = "/tmp/wordlists"
        for k, v in overrides.items():
            setattr(ctx, k, v)
        return ctx

    def test_wordlist_mode_default(self, tmp_path):
        """When cracked output exists, it becomes the default wordlist."""
        from hate_crack.attacks import markov_attack

        hash_file = str(tmp_path / "hashes.txt")
        cracked_out = hash_file + ".out"
        with open(cracked_out, "w") as f:
            f.write("Password1\nSummer2024\n")

        ctx = self._make_ctx(hcatHashFile=hash_file)
        with mock.patch("builtins.input", side_effect=["1", "n", ""]):
            markov_attack(ctx)

        ctx.hcatMarkov.assert_called_once_with(
            "0", hash_file, "wordlist", cracked_out, 5000,
        )

    def test_wordlist_mode_falls_back_to_config(self):
        """When cracked output does not exist, fall back to markovWordlist."""
        from hate_crack.attacks import markov_attack

        ctx = self._make_ctx(hcatHashFile="/tmp/nonexistent_hashes.txt")
        with mock.patch("builtins.input", side_effect=["1", "n", ""]):
            markov_attack(ctx)

        ctx.hcatMarkov.assert_called_once_with(
            "0", "/tmp/nonexistent_hashes.txt", "wordlist", "/tmp/wordlist.txt", 5000,
        )

    def test_wordlist_mode_custom_path(self):
        """Selection '1', override wordlist → resolved path passed to hcatMarkov."""
        from hate_crack.attacks import markov_attack

        ctx = self._make_ctx()
        ctx.select_file_with_autocomplete.return_value = "custom.txt"
        ctx._resolve_wordlist_path.return_value = "/resolved/custom.txt"

        with mock.patch("builtins.input", side_effect=["1", "y", ""]):
            markov_attack(ctx)

        ctx.select_file_with_autocomplete.assert_called_once()
        ctx._resolve_wordlist_path.assert_called_once_with("custom.txt", "/tmp/wordlists")
        ctx.hcatMarkov.assert_called_once_with(
            "0", "/tmp/hashes.txt", "wordlist", "/resolved/custom.txt", 5000,
        )

    def test_target_mode(self):
        """Selection '2' → hcatMarkov('target', {company, industry, location})."""
        from hate_crack.attacks import markov_attack

        ctx = self._make_ctx()
        with mock.patch("builtins.input", side_effect=["2", "AcmeCorp", "Finance", "NYC", ""]):
            markov_attack(ctx)

        ctx.hcatMarkov.assert_called_once()
        call_args = ctx.hcatMarkov.call_args
        assert call_args[0][2] == "target"
        target_info = call_args[0][3]
        assert target_info["company"] == "AcmeCorp"
        assert target_info["industry"] == "Finance"
        assert target_info["location"] == "NYC"

    def test_invalid_selection(self, capsys):
        """Selection '3' → 'Invalid selection.', no hcatMarkov call."""
        from hate_crack.attacks import markov_attack

        ctx = self._make_ctx()
        with mock.patch("builtins.input", side_effect=["3"]):
            markov_attack(ctx)

        captured = capsys.readouterr()
        assert "Invalid selection" in captured.out
        ctx.hcatMarkov.assert_not_called()

    def test_wordlist_list_uses_first(self):
        """When markovWordlist is a list and no cracked output exists, the first element is used."""
        from hate_crack.attacks import markov_attack

        ctx = self._make_ctx(
            hcatHashFile="/tmp/nonexistent_hashes.txt",
            markovWordlist=["/tmp/first.txt", "/tmp/second.txt"],
        )
        with mock.patch("builtins.input", side_effect=["1", "n", ""]):
            markov_attack(ctx)

        ctx.hcatMarkov.assert_called_once()
        call_args = ctx.hcatMarkov.call_args
        assert call_args[0][3] == "/tmp/first.txt"
