.DEFAULT_GOAL := submodules
.PHONY: install reinstall update dev-install dev-reinstall clean hashcat-utils submodules submodules-pre vendor-assets clean-vendor test coverage lint check ruff mypy

hashcat-utils: submodules
	$(MAKE) -C hashcat-utils

submodules:
	@# Initialize submodules when present
	@if [ -f .gitmodules ] && command -v git >/dev/null 2>&1; then \
		git submodule update --init --recursive; \
	fi; \
	$(MAKE) submodules-pre; \
	if [ -f .gitmodules ] && command -v git >/dev/null 2>&1; then \
		for path in $$(git config --file .gitmodules --get-regexp path | awk '{print $$2}'); do \
			if [ -f "$$path/Makefile" ] || [ -f "$$path/makefile" ]; then \
				$(MAKE) -C "$$path"; \
			fi; \
		done; \
	fi
		

submodules-pre:
	@# Pre-step: basic sanity checks and file generation before building submodules.
	@# Ensure required directories exist (whether as submodules or vendored copies).
	@test -d hashcat-utils || { echo "Error: missing required directory: hashcat-utils"; exit 1; }
	@test -d princeprocessor || { echo "Error: missing required directory: princeprocessor"; exit 1; }
	@test -d omen || { echo "Warning: missing directory: omen (OMEN attacks will not be available)"; }
	@# Keep per-length expander sources in sync (expander8.c..expander24.c).
	@# Patch hashcat-utils/src/Makefile so these new expanders are compiled by default.
	@bases="hashcat-utils hate_crack/hashcat-utils"; for base in $$bases; do src="$$base/src/expander.c"; test -f "$$src" || continue; for i in $$(seq 8 36); do dst="$$base/src/expander$$i.c"; if [ ! -f "$$dst" ]; then cp "$$src" "$$dst"; perl -pi -e "s/#define LEN_MAX 7/#define LEN_MAX $$i/g" "$$dst"; fi; done; mk="$$base/src/Makefile"; test -f "$$mk" || continue; exp_bins=""; exp_exes=""; for i in $$(seq 8 36); do exp_bins="$$exp_bins expander$$i.bin"; exp_exes="$$exp_exes expander$$i.exe"; done; EXP_BINS="$$exp_bins" perl -pi -e 'if(/^native:/ && index($$_, "expander8.bin") < 0){chomp; $$_ .= "$$ENV{EXP_BINS}"; $$_ .= "\n";}' "$$mk"; EXP_EXES="$$exp_exes" perl -pi -e 'if(/^windows:/ && index($$_, "expander8.exe") < 0){chomp; $$_ .= "$$ENV{EXP_EXES}"; $$_ .= "\n";}' "$$mk"; perl -0777 -pi -e 's/\n# Auto-added by hate_crack \\(submodules-pre\\)\n.*\z/\n/s' "$$mk"; printf '%s\n' '' '# Auto-added by hate_crack (submodules-pre)' 'expander%.bin: src/expander%.c' >> "$$mk"; printf '\t%s\n' '$${CC_NATIVE} $${CFLAGS_NATIVE} $${LDFLAGS_NATIVE} -o bin/$$@ $$<' >> "$$mk"; printf '%s\n' '' 'expander%.exe: src/expander%.c' >> "$$mk"; printf '\t%s\n' '$${CC_WINDOWS} $${CFLAGS_WINDOWS} -o bin/$$@ $$<' >> "$$mk"; done

vendor-assets:
	@if [ ! -f princeprocessor/pp64.bin ] && [ ! -f princeprocessor/pp64.app ] && [ ! -f princeprocessor/pp64.exe ]; then \
		echo "princeprocessor binaries are missing; please ensure the princeprocessor directory is present."; \
		exit 1; \
	fi
	@echo "Syncing assets into package for uv tool install..."
	@rm -rf hate_crack/hashcat-utils hate_crack/princeprocessor hate_crack/omen
	@cp -R hashcat-utils hate_crack/
	@cp -R princeprocessor hate_crack/
	@if [ -d omen ]; then \
		cp -R omen hate_crack/; \
		rm -rf hate_crack/omen/.git; \
	fi
	@rm -rf hate_crack/hashcat-utils/.git hate_crack/princeprocessor/.git

clean-vendor:
	@echo "Cleaning up vendored assets from working tree..."
	@rm -rf hate_crack/hashcat-utils hate_crack/princeprocessor hate_crack/omen

install: submodules vendor-assets
	@echo "Detecting OS and installing dependencies..."
	@if [ "$(shell uname)" = "Darwin" ]; then \
		echo "Detected macOS"; \
		command -v brew >/dev/null 2>&1 || { echo >&2 "Homebrew not found. Please install Homebrew first: https://brew.sh/"; exit 1; }; \
		brew install p7zip transmission-cli; \
	elif [ -f /etc/debian_version ]; then \
		echo "Detected Debian/Ubuntu"; \
		sudo apt-get update; \
		sudo apt-get install -y p7zip-full transmission-cli; \
	else \
		echo "Unsupported OS. Please install dependencies manually."; \
		exit 1; \
	fi
	@uv tool install -e . --force --reinstall

update: submodules vendor-assets
	@uv tool install -e . --force --reinstall

reinstall: uninstall install

dev-install:
	@echo "Installing project with development dependencies..."
	uv pip install -e ".[dev]"

dev-reinstall: uninstall dev-install


clean:
	-$(MAKE) -C hashcat-utils clean
	-@if [ -f .gitmodules ]; then git submodule deinit -f --all; fi
	rm -rf .pytest_cache .ruff_cache build dist *.egg-info
	rm -rf ~/.cache/uv
	find . -name "__pycache__" -type d -prune -exec rm -rf {} +

test:
	uv run pytest -v

coverage:
	uv run pytest --cov=hate_crack --cov-report=term-missing

ruff:
	uv run ruff check hate_crack

mypy:
	uv run mypy hate_crack

lint: ruff mypy
	@echo "✓ All linting checks passed"

check: lint
	@echo "✓ Code quality checks passed"

uninstall:
	@echo "Detecting OS and uninstalling dependencies..."
	@uv tool uninstall hate_crack || true
	@data_home="$${XDG_DATA_HOME:-$$HOME/.local/share}"; \
		rm -rf "$$data_home/uv/tools/hate-crack" "$$data_home/uv/tools/hate_crack"
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
