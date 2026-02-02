.DEFAULT_GOAL := submodules
.PHONY: install clean hashcat-utils submodules test

hashcat-utils: submodules
	$(MAKE) -C hashcat-utils

submodules:
	@# Initialize submodules when present
	@if [ -f .gitmodules ] && command -v git >/dev/null 2>&1; then \
		git submodule update --init --recursive; \
		for path in $$(git config --file .gitmodules --get-regexp path | awk '{print $$2}'); do \
			if [ -f "$$path/Makefile" ]; then \
				$(MAKE) -C "$$path"; \
			fi; \
		done; \
	fi

install: submodules
	@echo "Detecting OS and installing dependencies..."
	@if [ ! -d hashcat-utils/bin ] || [ -z "$$(ls -A hashcat-utils/bin 2>/dev/null)" ]; then \
		echo "hashcat-utils/bin is missing or empty; building hashcat-utils..."; \
		$(MAKE) -C hashcat-utils; \
	fi
	@if [ ! -f princeprocessor/pp64.bin ] && [ ! -f princeprocessor/pp64.app ] && [ ! -f princeprocessor/pp64.exe ]; then \
		echo "princeprocessor binaries are missing; please ensure the princeprocessor directory is present."; \
		exit 1; \
	fi
	@if [ "$(shell uname)" = "Darwin" ]; then \
		echo "Detected macOS"; \
		command -v brew >/dev/null 2>&1 || { echo >&2 "Homebrew not found. Please install Homebrew first: https://brew.sh/"; exit 1; }; \
		brew install p7zip transmission-cli; \
		echo "Syncing assets into package for uv tool install..."; \
		rm -rf hate_crack/hashcat-utils hate_crack/princeprocessor; \
		cp -R hashcat-utils hate_crack/; \
		cp -R princeprocessor hate_crack/; \
		rm -rf hate_crack/hashcat-utils/.git hate_crack/princeprocessor/.git; \
		uv tool install .; \
	elif [ -f /etc/debian_version ]; then \
		echo "Detected Debian/Ubuntu"; \
		sudo apt-get update; \
		sudo apt-get install -y p7zip-full transmission-cli; \
		echo "Syncing assets into package for uv tool install..."; \
		rm -rf hate_crack/hashcat-utils hate_crack/princeprocessor; \
		cp -R hashcat-utils hate_crack/; \
		cp -R princeprocessor hate_crack/; \
		rm -rf hate_crack/hashcat-utils/.git hate_crack/princeprocessor/.git; \
		uv tool install .; \
	else \
		echo "Unsupported OS. Please install dependencies manually."; \
		exit 1; \
	fi


clean:
	-$(MAKE) -C hashcat-utils clean
	-@if [ -f .gitmodules ]; then git submodule deinit -f --all; fi
	rm -rf .pytest_cache .ruff_cache build dist *.egg-info
	rm -rf ~/.cache/uv
	find . -name "__pycache__" -type d -prune -exec rm -rf {} +

test:
	uv run pytest -v


uninstall:
	@echo "Detecting OS and uninstalling dependencies..."
	@if [ "$(shell uname)" = "Darwin" ]; then \
		echo "Detected macOS"; \
		command -v brew >/dev/null 2>&1 || { echo >&2 "Homebrew not found. Please uninstall Homebrew packages manually."; exit 1; }; \
		brew uninstall --ignore-dependencies p7zip transmission-cli || true; \
		uv tool uninstall hate_crack || true; \
		rm -rf ~/.cache/uv; \
	elif [ -f /etc/debian_version ]; then \
		echo "Detected Debian/Ubuntu"; \
		sudo apt-get remove -y p7zip-full transmission-cli || true; \
		uv tool uninstall hate_crack || true; \
		rm -rf ~/.cache/uv; \
	else \
		echo "Unsupported OS. Please uninstall dependencies manually."; \
		exit 1; \
	fi
