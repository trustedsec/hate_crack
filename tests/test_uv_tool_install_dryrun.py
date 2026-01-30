from pathlib import Path
import tomllib


def test_uv_tool_install_dryrun_metadata():
    repo_root = Path(__file__).resolve().parents[1]
    pyproject_path = repo_root / "pyproject.toml"
    data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))

    build_system = data.get("build-system", {})
    assert build_system.get("build-backend") == "setuptools.build_meta"

    project = data.get("project", {})
    scripts = project.get("scripts", {})
    assert scripts.get("hate_crack") == "hate_crack.__main__:main"

    setuptools_find = data.get("tool", {}).get("setuptools", {}).get("packages", {}).get("find", {})
    assert "hate_crack*" in setuptools_find.get("include", [])

    entrypoint = repo_root / "hate_crack" / "__main__.py"
    assert entrypoint.is_file()
