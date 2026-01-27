PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
SCRIPT ?= hate_crack
WRAPPER_PATH := $(BINDIR)/$(SCRIPT)
PROJECT_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
ENTRYPOINT := $(PROJECT_ROOT)/hate_crack/hate_crack.py
UV ?= uv

.PHONY: install clean

install:
	@mkdir -p $(BINDIR)
	@printf '%s\n' "#!/bin/sh" "" "$(UV) run $(ENTRYPOINT) \"\$$@\"" > $(WRAPPER_PATH)
	@chmod +x $(WRAPPER_PATH)
	@echo "Installed $(WRAPPER_PATH)"

clean:
	@rm -f $(WRAPPER_PATH)
	@echo "Removed $(WRAPPER_PATH)"
