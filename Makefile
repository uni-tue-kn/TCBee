# Directory to output binaries to
BIN_DIR := bin
# Install locations, see `make install`
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
DESTDIR ?=
INSTALL ?= install
# Version stamped into the tcbee script
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
# Extra cargo flags for tcbee-process and tcbee-viz, for example
#   make process viz CARGO_FLAGS="--features bundled"
#   make process viz CARGO_FLAGS="--no-default-features --features sqlite"
# Use the same flags for both, so the dependencies (DuckDB!) are built only once.
CARGO_FLAGS ?=
# Available tcbee parts for clean all. tcbee-process and tcbee-viz share the workspace in ./
TCBEE_PARTS := . tcbee-record/ tcbee-live/
# Binaries to copy to BIN_DIR
BINARIES := tcbee-record/target/release/tcbee-record target/release/tcbee-process target/release/tcbee-viz tcbee-live/target/release/tcbee-live
# Files that `make install` installs and `make uninstall` removes
INSTALL_FILES := tcbee tcbee-record tcbee-process tcbee-viz tcbee-live

# Default target: build all projects and copy them to BIN_DIR
.PHONY: all
all: record process viz live

.PHONY: record
record:
	@echo "Building tcbee-record ..."
	cd tcbee-record && cargo build --release && cd ..
	$(MAKE) stage

.PHONY: process
process:
	@echo "Building tcbee-process ..."
	cargo build --release -p tcbee-process $(CARGO_FLAGS)
	$(MAKE) stage

.PHONY: viz
viz:
	@echo "Building tcbee-viz ..."
	cargo build --release -p tcbee-viz $(CARGO_FLAGS)
	$(MAKE) stage

.PHONY: live
live:
	@echo "Building tcbee-live ..."
	cd tcbee-live && cargo build --release && cd ..
	$(MAKE) stage

# Copy the built binaries and the tcbee script to BIN_DIR
.PHONY: stage
stage:
	@echo "Copying binaries to $(BIN_DIR)"
	@mkdir -p $(BIN_DIR)
	@for binary in $(BINARIES); do \
		if [ -f "$$binary" ]; then \
			cp "$$binary" "$(BIN_DIR)/"; \
		else \
			echo "No binary for '$$binary'"; \
		fi; \
	done
	@sed 's|@VERSION@|$(VERSION)|' tcbee > $(BIN_DIR)/tcbee
	@chmod 755 $(BIN_DIR)/tcbee
	@# Old checkouts used install/; keep it current for scripts that still point there
	@if [ -d install ]; then \
		echo "Also copying to install/ (old location, use $(BIN_DIR)/)"; \
		cp $(BIN_DIR)/* install/; \
	fi

# Install the script and the tools in BIN_DIR to $(DESTDIR)$(BINDIR); does not build, run `make` first.
# Tools that were not built are skipped.
.PHONY: install
install:
	@if [ ! -f $(BIN_DIR)/tcbee ]; then \
		echo "Nothing to install in $(BIN_DIR)/, run 'make' first"; \
		exit 1; \
	fi
	@for file in $(INSTALL_FILES); do \
		if [ -f "$(BIN_DIR)/$$file" ]; then \
			echo "Installing $(DESTDIR)$(BINDIR)/$$file"; \
			$(INSTALL) -D -m 755 "$(BIN_DIR)/$$file" "$(DESTDIR)$(BINDIR)/$$file" || exit 1; \
		fi; \
	done

.PHONY: uninstall
uninstall:
	@for file in $(INSTALL_FILES); do \
		rm -f "$(DESTDIR)$(BINDIR)/$$file"; \
	done

# Clean all rust building artifacts to save storage (~ 4GB)
.PHONY: clean
clean:
	@echo "Cleaning up..."
	@for project in $(TCBEE_PARTS); do \
		echo "Cleaning $$project"; \
		cd $$project && cargo clean && cd $(CURDIR); \
	done
	@rm -rf $(BIN_DIR)
	@echo "Clean complete."
