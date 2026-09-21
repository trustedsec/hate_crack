"""The coverage store must never resolve to the operator's real file in tests."""

import os
from pathlib import Path

from hate_crack import attack_coverage as ac


def test_get_store_never_resolves_under_real_home():
    store = ac.get_store()
    resolved = Path(store.path).resolve()
    forbidden = (Path.home() / ".hate_crack" / "coverage").resolve()
    assert forbidden not in resolved.parents, (
        f"get_store() resolved to {resolved}, inside the operator's real "
        "coverage directory. A test or agent command that calls get_store() "
        "would write to a multi-gigabyte store holding many engagements."
    )


def test_store_path_is_redirected_by_the_autouse_fixture(tmp_path):
    store = ac.get_store()
    assert str(tmp_path) in str(Path(store.path).resolve()) or str(
        Path(store.path).resolve()
    ).startswith(os.environ["HATE_CRACK_COVERAGE_DIR"])
