.PHONY: all install clean hashcat-utils

all: hashcat-utils

hashcat-utils:
	$(MAKE) -C hashcat-utils

install: hashcat-utils
	uv tool install .

clean:
	-$(MAKE) -C hashcat-utils clean
	rm -rf .pytest_cache .ruff_cache build dist *.egg-info
	find . -name "__pycache__" -type d -prune -exec rm -rf {} +
