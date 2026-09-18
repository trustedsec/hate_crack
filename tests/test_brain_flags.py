from hate_crack import attack_coverage, brain


def test_session_id_derives_from_the_coverage_target(tmp_path):
    hash_file = tmp_path / "hashes.txt"
    hash_file.write_text("$2a$05$abc\n")
    target = attack_coverage.target_id(str(hash_file))
    assert brain.session_id(str(hash_file)) == "0x" + target[:8]


def test_session_id_survives_a_rename(tmp_path):
    first = tmp_path / "a.txt"
    first.write_text("$2a$05$abc\n")
    before = brain.session_id(str(first))
    second = tmp_path / "b.txt"
    first.rename(second)
    attack_coverage.clear_target_memo()
    assert brain.session_id(str(second)) == before


def test_session_id_is_none_for_a_missing_file(tmp_path):
    assert brain.session_id(str(tmp_path / "nope.txt")) is None


def test_client_flags_assemble_in_hashcat_order():
    flags = brain.client_flags(
        host="127.0.0.1", port=6863, password="s3cret", features=3, session="0xdeadbeef"
    )
    assert flags == [
        "-z",
        "--brain-host",
        "127.0.0.1",
        "--brain-port",
        "6863",
        "--brain-password",
        "s3cret",
        "--brain-client-features",
        "3",
        "--brain-session",
        "0xdeadbeef",
    ]


def test_client_features_outside_one_to_three_falls_back_to_three():
    flags = brain.client_flags(
        host="127.0.0.1", port=6863, password="x", features=9, session="0xdeadbeef"
    )
    assert flags[flags.index("--brain-client-features") + 1] == "3"
