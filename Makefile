# Directory to output binaries to
INSTALL_DIR := install
# Extra cargo flags for tcbee-process and tcbee-viz, for example
#   make process viz CARGO_FLAGS="--features bundled"
#   make process viz CARGO_FLAGS="--no-default-features --features sqlite"
# Use the same flags for both, so the dependencies (DuckDB!) are built only once.
CARGO_FLAGS ?=
# Available tcbee parts for clean all. tcbee-process and tcbee-viz share the workspace in ./
TCBEE_PARTS := . tcbee-record/ tcbee-live/
# Binaries to copy for install
BINARIES := tcbee-record/target/release/tcbee-record target/release/tcbee-process target/release/tcbee-viz tcbee-live/target/release/tcbee-live

# Default target: build all projects and install them
.PHONY: all
all: record process viz live install

.PHONY: record
record:
	@echo "Building tcbee-record ..."
	cd tcbee-record && cargo build --release && cd ..
	$(MAKE) install

.PHONY: process
process:
	@echo "Building tcbee-process ..."
	cargo build --release -p tcbee-process $(CARGO_FLAGS)
	$(MAKE) install

.PHONY: viz
viz:
	@echo "Building tcbee-viz ..."
	cargo build --release -p tcbee-viz $(CARGO_FLAGS)
	$(MAKE) install

.PHONY: live
live:
	@echo "Building tcbee-live ..."
	cd tcbee-live && cargo build --release && cd ..
	$(MAKE) install

.PHONY: install
install:
	@echo "Copying binaries to $(INSTALL_DIR)"
	@mkdir -p $(INSTALL_DIR)
	@for binary in $(BINARIES); do \
		if [ -f "$$binary" ]; then \
			cp "$$binary" "$(INSTALL_DIR)/"; \
		else \
			echo "No binary for '$$binary'"; \
		fi; \
	done
# Copy run scipt
	@echo "Copying run script to $(INSTALL_DIR)"
	cp tcbee $(INSTALL_DIR)

# Clean all rust building artifacts to save storage (~ 4GB)
.PHONY: clean
clean:
	@echo "Cleaning up..."
	@for project in $(TCBEE_PARTS); do \
		echo "Cleaning $$project"; \
		cd $$project && cargo clean && cd $(CURDIR); \
	done
	@rm -rf $(INSTALL_DIR)
	@echo "Clean complete."
