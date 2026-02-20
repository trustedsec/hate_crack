.DEFAULT_GOAL := install
.PHONY: install reinstall update dev-install dev-reinstall clean hashcat-utils submodules submodules-pre vendor-assets clean-vendor test coverage lint check ruff ty

hashcat-utils: submodules
	$(MAKE) -C hashcat-utils

submodules:
	@# Initialize submodules only when inside a git repo (not in Docker/CI copies)
	@if [ -d .git ] && [ -f .gitmodules ] && command -v git >/dev/null 2>&1; then \
		git submodule update --init --recursive; \
	fi; \
	$(MAKE) submodules-pre; \
	if [ -f .gitmodules ] && command -v git >/dev/null 2>&1; then \
		for path in $$(git config --file .gitmodules --get-regexp path | awk '{print $$2}'); do \
			if [ "$$path" = "hashcat" ] && command -v hashcat >/dev/null 2>&1; then \
				echo "hashcat already installed in PATH, skipping submodule compilation"; \
				continue; \
			fi; \
			if [ "$$path" = "princeprocessor" ]; then \
				$(MAKE) -C "$$path/src" CFLAGS_LINUX64="-W -Wall -std=c99 -O2 -s -DLINUX"; \
				if [ -f "$$path/src/pp64.bin" ]; then cp "$$path/src/pp64.bin" "$$path/"; \
				elif [ -f "$$path/src/ppAppleArm64.bin" ]; then cp "$$path/src/ppAppleArm64.bin" "$$path/pp64.bin"; fi; \
				continue; \
			fi; \
			if [ -f "$$path/Makefile" ] || [ -f "$$path/makefile" ]; then \
				$(MAKE) -C "$$path"; \
			fi; \
		done; \
	fi
		

submodules-pre:
	@# Pre-step: basic sanity checks and file generation before building submodules.
	@# Ensure required directories exist (whether as submodules or vendored copies).
	@# hashcat is optional here: submodule is compiled if present, else PATH hashcat is used.
	@test -d hashcat || command -v hashcat >/dev/null 2>&1 || { \
		echo "Error: hashcat not found. Either initialize the hashcat submodule or install hashcat."; exit 1; }
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
	@rm -rf hate_crack/hashcat hate_crack/hashcat-utils hate_crack/princeprocessor hate_crack/omen
	@mkdir -p hate_crack/hashcat
	@if [ -f hashcat/hashcat ]; then \
		echo "Vendoring compiled hashcat submodule binary..."; \
		cp hashcat/hashcat hate_crack/hashcat/hashcat; \
		[ -d hashcat/rules ] && cp -R hashcat/rules hate_crack/hashcat/rules || true; \
		[ -d hashcat/OpenCL ] && cp -R hashcat/OpenCL hate_crack/hashcat/OpenCL || true; \
		[ -d hashcat/modules ] && cp -R hashcat/modules hate_crack/hashcat/modules || true; \
	elif [ -f hashcat/hashcat.app ]; then \
		echo "Vendoring compiled hashcat submodule binary (macOS app)..."; \
		cp hashcat/hashcat.app hate_crack/hashcat/hashcat; \
		[ -d hashcat/rules ] && cp -R hashcat/rules hate_crack/hashcat/rules || true; \
		[ -d hashcat/OpenCL ] && cp -R hashcat/OpenCL hate_crack/hashcat/OpenCL || true; \
		[ -d hashcat/modules ] && cp -R hashcat/modules hate_crack/hashcat/modules || true; \
	elif command -v hashcat >/dev/null 2>&1; then \
		HASHCAT_PATH=$$(command -v hashcat); \
		echo "Using system hashcat from $$HASHCAT_PATH..."; \
		cp "$$HASHCAT_PATH" hate_crack/hashcat/hashcat; \
		HASHCAT_DIR=$$(dirname $$(realpath "$$HASHCAT_PATH")); \
		[ -d "$$HASHCAT_DIR/rules" ] && cp -R "$$HASHCAT_DIR/rules" hate_crack/hashcat/rules || true; \
		[ -d "$$HASHCAT_DIR/OpenCL" ] && cp -R "$$HASHCAT_DIR/OpenCL" hate_crack/hashcat/OpenCL || true; \
		[ -d "$$HASHCAT_DIR/modules" ] && cp -R "$$HASHCAT_DIR/modules" hate_crack/hashcat/modules || true; \
	else \
		echo "Error: hashcat not found. Either compile the hashcat submodule or install hashcat."; \
		exit 1; \
	fi
	@cp -R hashcat-utils hate_crack/
	@cp -R princeprocessor hate_crack/
	@if [ -d omen ]; then \
		cp -R omen hate_crack/; \
		rm -rf hate_crack/omen/.git; \
	fi
	@rm -rf hate_crack/hashcat-utils/.git hate_crack/princeprocessor/.git

clean-vendor:
	@echo "Cleaning up vendored assets from working tree..."
	@rm -rf hate_crack/hashcat hate_crack/hashcat-utils hate_crack/princeprocessor hate_crack/omen

install: submodules vendor-assets
	@echo "Detecting OS and installing dependencies..."
	@if [ "$(shell uname)" = "Darwin" ]; then \
		echo "Detected macOS"; \
		xcode-select -p >/dev/null 2>&1 || { \
			echo "Xcode Command Line Tools not found. Installing..."; \
			xcode-select --install; \
			echo "Re-run 'make' after the Xcode CLT installation completes."; \
			exit 1; \
		}; \
		command -v brew >/dev/null 2>&1 || { echo >&2 "Homebrew not found. Please install Homebrew first: https://brew.sh/"; exit 1; }; \
		brew install p7zip transmission-cli; \
	elif [ -f /etc/debian_version ]; then \
		echo "Detected Debian/Ubuntu"; \
		command -v gcc >/dev/null 2>&1 || { sudo apt-get update && sudo apt-get install -y build-essential; }; \
		sudo apt-get update; \
		sudo apt-get install -y p7zip-full transmission-cli; \
	else \
		echo "Unsupported OS. Please install dependencies manually."; \
		exit 1; \
	fi
	@command -v uv >/dev/null 2>&1 || { echo "uv not found. Installing uv..."; curl -LsSf https://astral.sh/uv/install.sh | sh; }
	@uv tool install -e .

update: submodules vendor-assets
	@uv tool install -e . --force --reinstall

reinstall: uninstall install

dev-install:
	@echo "Installing project with development dependencies..."
	uv pip install -e ".[dev]"

dev-reinstall: uninstall dev-install


clean:
	-$(MAKE) -C hashcat-utils clean
	-$(MAKE) -C hashcat clean
	-@if [ -f .gitmodules ]; then git submodule deinit -f --all; fi
	rm -rf .pytest_cache .ruff_cache build dist *.egg-info
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
