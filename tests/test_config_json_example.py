import json
import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT_EXAMPLE = os.path.join(REPO_ROOT, "config.json.example")
PACKAGED_EXAMPLE = os.path.join(REPO_ROOT, "hate_crack", "config.json.example")


def test_packaged_example_is_symlink_to_root():
    assert os.path.islink(PACKAGED_EXAMPLE), (
        "hate_crack/config.json.example must be a symlink to the root "
        "config.json.example so there is a single source of truth for defaults"
    )


def test_packaged_and_root_examples_have_identical_content():
    with open(ROOT_EXAMPLE) as f:
        root_config = json.load(f)
    with open(PACKAGED_EXAMPLE) as f:
        packaged_config = json.load(f)

    assert packaged_config == root_config
