"""Diagnostics for the local Hashview stack harness.

These are offline: they exercise how `_hashview_local` *reports* failures, not
docker itself.
"""

import subprocess

from tests import _hashview_local as hv


def _failure(output):
    return subprocess.CalledProcessError(
        returncode=1, cmd=["docker", "compose", "up"], output=output
    )


def test_port_conflict_is_named_and_actionable():
    """A held host port must be reported as such, not as "exit status 1".

    hashview's compose file publishes fixed host ports and HASHVIEW_LOCAL_PORT
    only moves the app's SERVER_NAME, so a second hashview project silently owns
    them and no env var gets this stack out of the way. Reported opaquely, the
    live tests skip for a reason that reads like docker being broken -- which
    cost real time twice while investigating #223 and #225.
    """
    output = (
        "Error response from daemon: failed to set up container networking: "
        "driver failed programming external connectivity on endpoint "
        "hashview-db-1 (abc123): Bind for 0.0.0.0:3306 failed: port is already "
        "allocated\n"
    )
    reason = hv._describe_compose_up_failure(_failure(output))

    assert "3306" in reason
    assert "already allocated" in reason
    # The operator needs to know how to find the offender, not just that one
    # exists.
    assert "docker ps --filter publish=3306" in reason
    # And that pointing at an existing instance is a way out.
    assert "HASHVIEW_URL" in reason


def test_port_conflict_regex_handles_a_bare_port():
    """Docker has emitted both "0.0.0.0:3306" and a bare "3306" over versions."""
    reason = hv._describe_compose_up_failure(
        _failure("Bind for 5000 failed: port is already allocated")
    )
    assert "5000" in reason
    assert "docker ps --filter publish=5000" in reason


def test_non_port_failure_surfaces_the_last_output_line():
    """Any other failure must still say something specific.

    Previously every failure collapsed to the CalledProcessError repr, which
    names the command and the exit code and nothing about the cause.
    """
    reason = hv._describe_compose_up_failure(
        _failure(
            "Step 3/9 : RUN pip install -r requirements.txt\nERROR: no matching distribution found for hashview-dep==9.9.9\n"
        )
    )
    assert "no matching distribution found" in reason
    assert "docker compose up failed" in reason


def test_empty_output_still_produces_a_reason():
    """`capture=True` should always give output, but never return an empty reason."""
    reason = hv._describe_compose_up_failure(_failure(""))
    assert reason.strip()
    assert "docker compose up failed" in reason
