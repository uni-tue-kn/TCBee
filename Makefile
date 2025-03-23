# Directory to output binaries to
INSTALL_DIR := install
# Available tcbee parts for clean all
TCBEE_PARTS := tcbee-record/ tcbee-process/ tcbee-viz/
# Binaries to copy for install
BINARIES := tcbee-record/target/release/tcbee-record tcbee-process/target/release/tcbee-process tcbee-viz/target/release/tcbee-viz

# Default target: build all projects and install them
.PHONY: all
all: record process viz install

.PHONY: record
record:
	@echo "Building tcbee-record ..."
	cd tcbee-record && cargo build --release && cd ..
	$(MAKE) install

.PHONY: process
process:
	@echo "Building tcbee-process ..."
	cd tcbee-process && cargo build --release && cd ..
	$(MAKE) install

.PHONY: viz
viz:
	@echo "Building tcbee-viz ..."
	cd tcbee-viz && cargo build --release && cd ..
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