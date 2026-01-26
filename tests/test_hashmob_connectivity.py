def test_hashmob_connectivity_mocked(monkeypatch, capsys):
    from hate_crack import hashmob_wordlist as hm

    class FakeResp:
        def raise_for_status(self):
            return None

        def json(self):
            return [
                {"type": "wordlist", "name": "List A", "information": "Info A"},
                {"type": "wordlist", "name": "List B", "information": "Info B"},
                {"type": "other", "name": "Ignore", "information": "Nope"},
            ]

    def fake_get(url, headers=None, timeout=None):
        assert url == "https://hashmob.net/api/v2/resource"
        assert headers == {"api-key": "test-key"}
        return FakeResp()

    monkeypatch.setattr(hm, "get_api_key", lambda: "test-key")
    monkeypatch.setattr(hm.requests, "get", fake_get)

    result = hm.download_hashmob_wordlist_list()
    assert len(result) == 2
    assert result[0]["name"] == "List A"
    assert result[1]["name"] == "List B"

    captured = capsys.readouterr()
    assert "Available Hashmob Wordlists:" in captured.out
    assert "List A" in captured.out
    assert "List B" in captured.out
