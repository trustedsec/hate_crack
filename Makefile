.DEFAULT_GOAL := install
.PHONY: install reinstall update dev-install dev-reinstall clean hashcat-utils submodules submodules-pre test coverage lint check ruff ty

hashcat-utils: submodules
	$(MAKE) -C hashcat-utils

submodules:
	@# Initialize submodules only when inside a git repo (not in Docker/CI copies)
	@if [ -d .git ] && [ -f .gitmodules ] && command -v git >/dev/null 2>&1; then \
		git submodule update --init --recursive; \
	fi
	@$(MAKE) submodules-pre
	@if [ -f .gitmodules ] && command -v git >/dev/null 2>&1; then \
		for path in $$(git config --file .gitmodules --get-regexp path | awk '{print $$2}'); do \
			if [ "$$path" = "princeprocessor" ]; then \
				if [ -f "$$path/pp64.bin" ]; then \
					echo "[submodules] princeprocessor already built, skipping"; \
				else \
					$(MAKE) -C "$$path/src" CFLAGS_LINUX64="-W -Wall -std=c99 -O2 -s -DLINUX"; \
					if [ -f "$$path/src/pp64.bin" ]; then cp "$$path/src/pp64.bin" "$$path/"; \
					elif [ -f "$$path/src/ppAppleArm64.bin" ]; then cp "$$path/src/ppAppleArm64.bin" "$$path/pp64.bin"; fi; \
				fi; \
				continue; \
			fi; \
			if [ -f "$$path/Makefile" ] || [ -f "$$path/makefile" ]; then \
				if [ "$$path" = "hashcat-utils" ] && [ -f "$$path/bin/expander.bin" ]; then \
					echo "[submodules] hashcat-utils already built, skipping"; \
				else \
					$(MAKE) -C "$$path"; \
				fi; \
			fi; \
		done; \
	fi

submodules-pre:
	@test -d hashcat-utils || { echo "Error: missing required directory: hashcat-utils"; exit 1; }
	@test -d princeprocessor || { echo "Error: missing required directory: princeprocessor"; exit 1; }
	@test -d omen || { echo "Warning: missing directory: omen (OMEN attacks will not be available)"; }
	@# Generate per-length expander sources (expander8.c..expander36.c) and patch
	@# hashcat-utils Makefiles to compile them. Skips if expander8.c already exists.
	@for base in hashcat-utils; do \
		src="$$base/src/expander.c"; \
		test -f "$$src" || continue; \
		test -f "$$base/src/expander8.c" && continue; \
		for i in $$(seq 8 36); do \
			dst="$$base/src/expander$$i.c"; \
			if [ ! -f "$$dst" ]; then \
				cp "$$src" "$$dst"; \
				perl -pi -e "s/#define LEN_MAX 7/#define LEN_MAX $$i/g" "$$dst"; \
			fi; \
		done; \
		mk="$$base/src/Makefile"; \
		test -f "$$mk" || continue; \
		exp_bins=""; exp_exes=""; \
		for i in $$(seq 8 36); do \
			exp_bins="$$exp_bins expander$$i.bin"; \
			exp_exes="$$exp_exes expander$$i.exe"; \
		done; \
		EXP_BINS="$$exp_bins" perl -pi -e \
			'if(/^native:/ && index($$_, "expander8.bin") < 0){chomp; $$_ .= "$$ENV{EXP_BINS}\n";}' "$$mk"; \
		EXP_EXES="$$exp_exes" perl -pi -e \
			'if(/^windows:/ && index($$_, "expander8.exe") < 0){chomp; $$_ .= "$$ENV{EXP_EXES}\n";}' "$$mk"; \
		perl -0777 -pi -e 's/\n# Auto-added by hate_crack \\(submodules-pre\\)\n.*\z/\n/s' "$$mk"; \
		printf '%s\n' '' '# Auto-added by hate_crack (submodules-pre)' 'expander%.bin: src/expander%.c' >> "$$mk"; \
		printf '\t%s\n' '$${CC_NATIVE} $${CFLAGS_NATIVE} $${LDFLAGS_NATIVE} -o bin/$$@ $$<' >> "$$mk"; \
		printf '%s\n' '' 'expander%.exe: src/expander%.c' >> "$$mk"; \
		printf '\t%s\n' '$${CC_WINDOWS} $${CFLAGS_WINDOWS} -o bin/$$@ $$<' >> "$$mk"; \
	done

install: submodules
	@echo "Installing dependencies..."
	@if [ "$(shell uname)" = "Darwin" ]; then \
		echo "Detected macOS"; \
		xcode-select -p >/dev/null 2>&1 || { \
			echo "Xcode Command Line Tools not found. Installing..."; \
			xcode-select --install; \
			echo "Re-run 'make' after the Xcode CLT installation completes."; \
			exit 1; \
		}; \
		command -v brew >/dev/null 2>&1 || { echo >&2 "Homebrew not found. Please install Homebrew first: https://brew.sh/"; exit 1; }; \
		command -v 7z >/dev/null 2>&1 || brew install p7zip; \
		command -v transmission-cli >/dev/null 2>&1 || brew install transmission-cli; \
	elif [ -f /etc/debian_version ]; then \
		echo "Detected Debian/Ubuntu"; \
		command -v gcc >/dev/null 2>&1 || { sudo apt-get update && sudo apt-get install -y build-essential; }; \
		NEED_INSTALL=""; \
		command -v 7z >/dev/null 2>&1 || NEED_INSTALL="$$NEED_INSTALL p7zip-full"; \
		command -v transmission-cli >/dev/null 2>&1 || NEED_INSTALL="$$NEED_INSTALL transmission-cli"; \
		if [ -n "$$NEED_INSTALL" ]; then \
			sudo apt-get update && sudo apt-get install -y $$NEED_INSTALL; \
		fi; \
	else \
		echo "Unsupported OS. Please install dependencies manually."; \
		exit 1; \
	fi
	@command -v uv >/dev/null 2>&1 || { echo "uv not found. Installing uv..."; curl -LsSf https://astral.sh/uv/install.sh | sh; }
	@rm -f hate_crack/_version.py
	@UV_BIN=$$(command -v uv 2>/dev/null || echo "$$HOME/.local/bin/uv"); \
		"$$UV_BIN" sync
	@mkdir -p "$${XDG_BIN_HOME:-$$HOME/.local/bin}"
	@printf '#!/usr/bin/env bash\nset -euo pipefail\nexport HATE_CRACK_ORIG_CWD="$$PWD"\nexec uv run --directory %s python -m hate_crack "$$@"\n' "$(CURDIR)" \
		> "$${XDG_BIN_HOME:-$$HOME/.local/bin}/hate_crack"
	@chmod +x "$${XDG_BIN_HOME:-$$HOME/.local/bin}/hate_crack"
	@echo "Installed hate_crack shim to $${XDG_BIN_HOME:-$$HOME/.local/bin}/hate_crack"

update: submodules
	@uv sync
	@mkdir -p "$${XDG_BIN_HOME:-$$HOME/.local/bin}"
	@printf '#!/usr/bin/env bash\nset -euo pipefail\nexport HATE_CRACK_ORIG_CWD="$$PWD"\nexec uv run --directory %s python -m hate_crack "$$@"\n' "$(CURDIR)" \
		> "$${XDG_BIN_HOME:-$$HOME/.local/bin}/hate_crack"
	@chmod +x "$${XDG_BIN_HOME:-$$HOME/.local/bin}/hate_crack"
	@echo "Updated hate_crack shim at $${XDG_BIN_HOME:-$$HOME/.local/bin}/hate_crack"

reinstall: uninstall install

dev-install:
	@echo "Installing project with development dependencies..."
	uv pip install -e ".[dev]"

dev-reinstall: uninstall dev-install


clean:
	-$(MAKE) -C hashcat-utils clean
	-@if [ -f .gitmodules ]; then git submodule deinit -f --all; fi
	rm -rf .pytest_cache .ruff_cache build dist *.egg-info hate_crack/_version.py
	rm -rf ~/.cache/uv
	find . -name "__pycache__" -type d -prune -exec rm -rf {} +

test:
	@# Auto-set HATE_CRACK_SKIP_INIT when hashcat-utils binaries are not built
	@if [ -z "$$HATE_CRACK_SKIP_INIT" ] && [ ! -f hate_crack/hashcat-utils/bin/expander.bin ] && [ ! -f hate_crack/hashcat-utils/bin/expander.app ]; then \
		echo "[test] hashcat-utils not built, setting HATE_CRACK_SKIP_INIT=1"; \
		export HATE_CRACK_SKIP_INIT=1; \
	fi; \
	HATE_CRACK_SKIP_INIT=$${HATE_CRACK_SKIP_INIT:-1} uv run pytest -v

coverage:
	@if [ -z "$$HATE_CRACK_SKIP_INIT" ] && [ ! -f hate_crack/hashcat-utils/bin/expander.bin ] && [ ! -f hate_crack/hashcat-utils/bin/expander.app ]; then \
		echo "[coverage] hashcat-utils not built, setting HATE_CRACK_SKIP_INIT=1"; \
	fi; \
	HATE_CRACK_SKIP_INIT=$${HATE_CRACK_SKIP_INIT:-1} uv run pytest --cov=hate_crack --cov-report=term-missing

ruff:
	uv run ruff check hate_crack

ty:
	uv run ty check hate_crack

lint: ruff ty
	@echo "All linting checks passed"

check: lint
	@echo "Code quality checks passed"

uninstall:
	@echo "Detecting OS and uninstalling dependencies..."
	@bin_home="$${XDG_BIN_HOME:-$$HOME/.local/bin}"; \
		rm -f "$$bin_home/hate_crack"
	@if [ "$(shell uname)" = "Darwin" ]; then \
		echo "Detected macOS"; \
		command -v brew >/dev/null 2>&1 || { echo >&2 "Homebrew not found. Please uninstall Homebrew packages manually."; exit 1; }; \
		brew uninstall --ignore-dependencies p7zip transmission-cli || true; \
		rm -rf ~/.cache/uv; \
	elif [ -f /etc/debian_version ]; then \
		echo "Detected Debian/Ubuntu"; \
		sudo apt-get remove -y p7zip-full transmission-cli || true; \
		rm -rf ~/.cache/uv; \
	else \
		echo "Unsupported OS. Please uninstall dependencies manually."; \
		exit 1; \
	fi
