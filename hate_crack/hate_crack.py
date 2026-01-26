#!/usr/bin/env python3
import os
import sys


def _resolve_root():
    return os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, "hate_crack.py"))


def _load_root_module():
    root_path = _resolve_root()
    if not os.path.isfile(root_path):
        raise FileNotFoundError(f"Root hate_crack.py not found at {root_path}")
    import importlib.util
    spec = importlib.util.spec_from_file_location("hate_crack_root", root_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_ROOT = _load_root_module()
for _name, _value in _ROOT.__dict__.items():
    if _name.startswith("__") and _name not in {"__all__", "__doc__", "__name__", "__package__", "__loader__", "__spec__"}:
        continue
    globals().setdefault(_name, _value)


def cli_main():
    if hasattr(_ROOT, "cli_main"):
        return _ROOT.cli_main()
    if hasattr(_ROOT, "main"):
        return _ROOT.main()
    raise AttributeError("Root hate_crack.py has no cli_main or main")


if __name__ == "__main__":
    sys.exit(cli_main())
