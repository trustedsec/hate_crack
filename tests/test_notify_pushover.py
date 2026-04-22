"""Unit tests for the Pushover HTTP backend."""
from unittest.mock import MagicMock, patch

from hate_crack.notify import pushover


def _mock_response(status_code: int = 200) -> MagicMock:
    r = MagicMock()
    r.status_code = status_code
    return r


class TestSendPushoverSuccess:
    def test_returns_true_on_http_200(self) -> None:
        with patch.object(pushover, "requests") as mock_requests:
            mock_requests.post.return_value = _mock_response(200)
            ok = pushover._send_pushover("tok", "usr", "title", "msg")
        assert ok is True

    def test_payload_has_no_plaintext(self) -> None:
        with patch.object(pushover, "requests") as mock_requests:
            mock_requests.post.return_value = _mock_response(200)
            pushover._send_pushover("tok", "usr", "Crack complete", "alice cracked")
            (url,), kwargs = mock_requests.post.call_args
        assert url == pushover.PUSHOVER_URL
        data = kwargs["data"]
        assert set(data.keys()) == {"token", "user", "title", "message"}
        assert data["token"] == "tok"
        assert data["user"] == "usr"
        # The whole payload is just title + message + creds. No 'password',
        # 'hash', 'plaintext' or similar keys ever appear.
        assert "password" not in data
        assert "plaintext" not in data
        assert "hash" not in data

    def test_timeout_is_passed(self) -> None:
        with patch.object(pushover, "requests") as mock_requests:
            mock_requests.post.return_value = _mock_response(200)
            pushover._send_pushover("tok", "usr", "t", "m")
            _, kwargs = mock_requests.post.call_args
        assert kwargs["timeout"] == 10


class TestSendPushoverFailureModes:
    def test_missing_token_returns_false_without_calling_requests(self) -> None:
        with patch.object(pushover, "requests") as mock_requests:
            ok = pushover._send_pushover("", "usr", "t", "m")
        assert ok is False
        mock_requests.post.assert_not_called()

    def test_missing_user_returns_false(self) -> None:
        with patch.object(pushover, "requests") as mock_requests:
            ok = pushover._send_pushover("tok", "", "t", "m")
        assert ok is False
        mock_requests.post.assert_not_called()

    def test_network_error_returns_false(self) -> None:
        with patch.object(pushover, "requests") as mock_requests:
            mock_requests.post.side_effect = ConnectionError("refused")
            ok = pushover._send_pushover("tok", "usr", "t", "m")
        assert ok is False

    def test_generic_exception_returns_false(self) -> None:
        with patch.object(pushover, "requests") as mock_requests:
            mock_requests.post.side_effect = RuntimeError("boom")
            ok = pushover._send_pushover("tok", "usr", "t", "m")
        assert ok is False

    def test_non_200_response_returns_false(self) -> None:
        with patch.object(pushover, "requests") as mock_requests:
            mock_requests.post.return_value = _mock_response(500)
            ok = pushover._send_pushover("tok", "usr", "t", "m")
        assert ok is False

    def test_missing_requests_returns_false(self) -> None:
        with patch.object(pushover, "requests", None):
            ok = pushover._send_pushover("tok", "usr", "t", "m")
        assert ok is False

    def test_never_raises(self) -> None:
        # Even if requests.post returns something weird (no status_code),
        # the function must not raise.
        bad = MagicMock()
        # Accessing .status_code returns a non-int Mock — it will not equal 200.
        with patch.object(pushover, "requests") as mock_requests:
            mock_requests.post.return_value = bad
            ok = pushover._send_pushover("tok", "usr", "t", "m")
        assert ok is False
