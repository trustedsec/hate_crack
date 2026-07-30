import pytest


class TestGetAttrProxy:
    def test_known_attribute_proxied(self, hc_module):
        """Accessing a known main.py global via hc_module returns main's value."""
        val = hc_module._main.debug_mode
        assert hc_module.debug_mode == val

    def test_nonexistent_attribute_raises(self, hc_module):
        """Accessing a nonexistent attribute raises AttributeError."""
        with pytest.raises(AttributeError):
            _ = hc_module.this_attribute_does_not_exist_xyz

    def test_getattr_returns_main_function(self, hc_module):
        """Functions defined in main.py are accessible via the proxy."""
        assert callable(hc_module.generate_session_id)


class TestSyncGlobalsToMain:
    @pytest.mark.parametrize(
        "name,value",
        [
            ("hcatHashType", "9999"),
            ("hcatHashFile", "/tmp/synced.txt"),
            ("hcatHashFileOrig", "/tmp/orig.txt"),
            ("pipalPath", "/tmp/pipal"),
            ("pipal_count", 42),
            ("debug_mode", True),
        ],
    )
    def test_syncs_global(self, hc_module, name, value):
        """Setting a synced name in hc_module.__dict__ and calling sync propagates to main."""
        hc_module.__dict__[name] = value
        hc_module._sync_globals_to_main()
        assert getattr(hc_module._main, name) == value

    def test_only_syncs_listed_names(self, hc_module):
        """Names not in the sync list are not pushed to main."""
        hc_module.__dict__["_random_unlisted_var"] = "should_not_sync"
        hc_module._sync_globals_to_main()
        assert (
            getattr(hc_module._main, "_random_unlisted_var", None) != "should_not_sync"
        )

    def test_absent_name_skipped(self, hc_module):
        """If a synced name is absent from hc_module globals, main is not modified."""
        hc_module.__dict__.pop("pipal_count", None)
        original = getattr(hc_module._main, "pipal_count", None)
        hc_module._sync_globals_to_main()
        assert getattr(hc_module._main, "pipal_count", None) == original

    def test_does_not_clobber_a_value_main_set(self, hc_module):
        """A value main() itself set must survive the sync, even though the shim
        still carries a stale import-time copy of the same name in its globals.

        This is the #213 proxy clobber: hc_module's globals snapshot
        hate_crack.main's values at import time and never change unless a test
        (or hate_crack.py code) explicitly assigns them. Before the
        import-time-snapshot guard, calling _sync_globals_to_main() (which
        cli_main()/pipal() do on every call) would push that stale copy back
        over whatever main() had legitimately assigned in the meantime.
        """
        sentinel = "/tmp/set-by-main-not-the-shim.txt"
        hc_module._main.hcatHashFile = sentinel
        hc_module._sync_globals_to_main()
        assert hc_module._main.hcatHashFile == sentinel

    def test_still_syncs_a_value_genuinely_set_on_the_shim(self, hc_module):
        """The snapshot guard must not disable syncing outright: a value set on
        the shim's own globals (not just on main) still propagates.
        """
        hc_module.__dict__["hcatHashFile"] = "/tmp/set-on-the-shim.txt"
        hc_module._sync_globals_to_main()
        assert hc_module._main.hcatHashFile == "/tmp/set-on-the-shim.txt"


class TestSyncCallablesToMain:
    def test_syncs_callable_to_main(self, hc_module):
        """A callable set in hc_module.__dict__ is pushed to main."""

        def fake_fn():
            return "fake"

        hc_module.__dict__["quit_hc"] = fake_fn
        hc_module._sync_callables_to_main()
        assert hc_module._main.quit_hc is fake_fn

    def test_syncs_show_results(self, hc_module):
        """show_results callable is pushed to main when present."""

        def fake_fn():
            return "results"

        hc_module.__dict__["show_results"] = fake_fn
        hc_module._sync_callables_to_main()
        assert hc_module._main.show_results is fake_fn

    def test_skips_when_not_in_globals(self, hc_module):
        """If a callable name is absent from hc_module globals, main is unchanged."""
        original = getattr(hc_module._main, "show_readme", None)
        hc_module.__dict__.pop("show_readme", None)
        hc_module._sync_callables_to_main()
        assert getattr(hc_module._main, "show_readme", None) == original

    def test_all_callable_names_sync(self, hc_module):
        """All callable names in the sync list are pushed when present."""
        names = [
            "weakpass_wordlist_menu",
            "download_hashmob_wordlists",
            "download_hashmob_rules",
            "hashview_api",
            "export_excel",
            "show_results",
            "show_readme",
            "quit_hc",
        ]

        def make_fn(n: str):
            def fn() -> str:
                return n

            return fn

        fakes = {name: make_fn(name) for name in names}
        for name, fn in fakes.items():
            hc_module.__dict__[name] = fn
        hc_module._sync_callables_to_main()
        for name, fn in fakes.items():
            assert getattr(hc_module._main, name) is fn


class TestHashfileGlobalsHaveImportTimeDefaults:
    """#213: hcatHashFile, hcatHashFileOrig, and hcatHashType used to be
    assigned only inside main(), so they did not exist at import. That forced
    every test touching them to pass raising=False to monkeypatch.setattr,
    which silently creates the attribute on a typo instead of failing. They
    now have module-level defaults, matching the types main() assigns.
    """

    def test_defaults_at_a_fresh_import(self):
        """hate_crack.main is session-shared and other tests in this suite
        legitimately mutate hcatHashFile/hcatHashFileOrig/hcatHashType, so
        asserting their value against an already-imported module instance is
        order-dependent. Import in a subprocess instead, to observe the
        actual module-level defaults untouched by any test.
        """
        import subprocess
        import sys

        script = (
            "import os\n"
            "os.environ['HATE_CRACK_SKIP_INIT'] = '1'\n"
            "import hate_crack.main as m\n"
            "assert isinstance(m.hcatHashFile, str), repr(m.hcatHashFile)\n"
            "assert m.hcatHashFile == '', repr(m.hcatHashFile)\n"
            "assert m.hcatHashFileOrig is None, repr(m.hcatHashFileOrig)\n"
            "assert isinstance(m.hcatHashType, str), repr(m.hcatHashType)\n"
            "assert m.hcatHashType == '', repr(m.hcatHashType)\n"
            "print('OK')\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "OK" in result.stdout

    def test_typo_protection_restored(self, hc_module, monkeypatch):
        """monkeypatch.setattr (default raising=True) must reject a misspelled
        global name rather than silently creating a new attribute. This is
        the concrete regression #213 restores: before the module-level
        defaults existed, hcatHashFile/hcatHashFileOrig/hcatHashType were
        absent at import, so every call site needed raising=False, and that
        flag would just as happily accept "hcatHashfile" (wrong case).
        """
        import pytest

        with pytest.raises(AttributeError):
            monkeypatch.setattr(
                hc_module._main, "hcatHashfile", "wrong case, should not exist"
            )


class TestSymbolReexport:
    def test_main_function_accessible(self, hc_module):
        """Functions from main.py should be accessible on hc_module."""
        assert callable(getattr(hc_module, "hcatBruteForce", None))

    def test_hc_module_has_main_ref(self, hc_module):
        """hc_module._main should be the hate_crack.main module."""
        import hate_crack.main as main_mod

        assert hc_module._main is main_mod

    def test_debug_mode_reexported(self, hc_module):
        """Module-level globals from main.py appear on hc_module at load time."""
        assert hasattr(hc_module, "debug_mode")

    def test_generate_session_id_reexported(self, hc_module):
        """generate_session_id from main.py is accessible directly on hc_module."""
        fn = getattr(hc_module, "generate_session_id", None)
        assert callable(fn)
