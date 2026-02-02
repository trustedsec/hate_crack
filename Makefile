.PHONY: install clean hashcat-utils test

hashcat-utils:
	$(MAKE) -C hashcat-utils

install:
	@echo "Detecting OS and installing dependencies..."
	@if [ "$(shell uname)" = "Darwin" ]; then \
		echo "Detected macOS"; \
		command -v brew >/dev/null 2>&1 || { echo >&2 "Homebrew not found. Please install Homebrew first: https://brew.sh/"; exit 1; }; \
		brew install p7zip transmission-cli; \
		uv tool install .; \
	elif [ -f /etc/debian_version ]; then \
		echo "Detected Debian/Ubuntu"; \
		sudo apt-get update; \
		sudo apt-get install -y p7zip-full transmission-cli; \
		uv tool install .; \
	else \
		echo "Unsupported OS. Please install dependencies manually."; \
		exit 1; \
	fi


clean:
	-$(MAKE) -C hashcat-utils clean
	rm -rf .pytest_cache .ruff_cache build dist *.egg-info
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
	elif [ -f /etc/debian_version ]; then \
		echo "Detected Debian/Ubuntu"; \
		sudo apt-get remove -y p7zip-full transmission-cli || true; \
		uv tool uninstall hate_crack || true; \
	else \
		echo "Unsupported OS. Please uninstall dependencies manually."; \
		exit 1; \
	fi
