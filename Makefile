# Makefile for tcp-syn-stop suite (C + Rust)

APP := tcp_syn_stop
TUI_APP := syn-sight
INTEL_APP := syn-intel
SRC_DIR := src
OBJ_DIR         := .obj
DEBUG_OBJ_DIR   := .obj/debug
RELEASE_OBJ_DIR := .obj/release
TUI_DIR := syn-sight
INTEL_DIR := syn-intel
VERSION := $(shell cat VERSION)
DEB_MAINTAINER ?= Maintainer <maintainer@example.com>

# Reproducible builds: derive dates from last commit timestamp
SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct 2>/dev/null || date +%s)
BUILD_DATE := $(shell date -u -d @$(SOURCE_DATE_EPOCH) +%Y-%m-%d 2>/dev/null \
              || date -u -r $(SOURCE_DATE_EPOCH) +%Y-%m-%d)
BUILD_DATE_RFC2822 := $(shell date -u -d @$(SOURCE_DATE_EPOCH) -R 2>/dev/null \
                      || date -u -r $(SOURCE_DATE_EPOCH) +"%a, %d %b %Y %T %z")

# Embed version info into the binary
GIT_HASH := $(shell git describe --always --dirty 2>/dev/null || echo "unknown")
VERSION_DEFS := -DAPP_VERSION=\"$(VERSION)\" -DGIT_HASH=\"$(GIT_HASH)\"

BPF_C := $(SRC_DIR)/$(APP).bpf.c
BPF_OBJ := $(OBJ_DIR)/$(APP).bpf.o
SKEL_H := $(OBJ_DIR)/$(APP).skel.h
USER_C := $(SRC_DIR)/$(APP).c
USER_OBJ := $(OBJ_DIR)/$(APP).o
UTILS_OBJ      := $(OBJ_DIR)/utils.o
LOGGING_OBJ    := $(OBJ_DIR)/logging.o
CONFIG_OBJ     := $(OBJ_DIR)/config.o
BPF_LOADER_OBJ := $(OBJ_DIR)/bpf_loader.o

# Toolchain flags
CLANG ?= clang
BPFTOOL ?= bpftool
COMMON_WARNS   := -Wall -Wextra -Wshadow -Wstrict-prototypes -Werror=implicit-function-declaration -MMD -MP
DEBUG_CFLAGS    := -O0 -g3 -DDEBUG $(COMMON_WARNS) -Wpedantic -fanalyzer -fPIE -fstack-protector-strong $(VERSION_DEFS)
RELEASE_CFLAGS  := -O2 -g $(COMMON_WARNS) -DNDEBUG -D_FORTIFY_SOURCE=2 -fPIE -fstack-protector-strong $(VERSION_DEFS)
SANITIZE_CFLAGS := -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
                   $(COMMON_WARNS) -D_FORTIFY_SOURCE=2 -fPIE -fstack-protector-strong $(VERSION_DEFS)
TSAN_CFLAGS     := -O1 -g -fsanitize=thread -fno-omit-frame-pointer \
                   $(COMMON_WARNS) -D_FORTIFY_SOURCE=2 -fPIE -fstack-protector-strong $(VERSION_DEFS)
CFLAGS          := $(RELEASE_CFLAGS)
SANITIZE_OBJ_DIR := .obj/sanitize
TSAN_OBJ_DIR     := .obj/tsan
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_x86
INCLUDES := -I$(OBJ_DIR) -isystem /usr/include
LDFLAGS := -pie -Wl,-z,relro,-z,now -lbpf -lelf -lz -lnftables -lcap

all: $(APP) $(TUI_APP) $(INTEL_APP)

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(OBJ_DIR)/vmlinux.h: | $(OBJ_DIR)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPF_OBJ): $(BPF_C) $(OBJ_DIR)/vmlinux.h | $(OBJ_DIR)
	$(CLANG) $(BPF_CFLAGS) $(INCLUDES) -c $< -o $@

$(SKEL_H): $(BPF_OBJ) | $(OBJ_DIR)
	$(BPFTOOL) gen skeleton $< > $@

$(UTILS_OBJ): $(SRC_DIR)/utils.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(LOGGING_OBJ): $(SRC_DIR)/logging.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(CONFIG_OBJ): $(SRC_DIR)/config.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(BPF_LOADER_OBJ): $(SRC_DIR)/bpf_loader.c $(SKEL_H) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(USER_OBJ): $(USER_C) $(SKEL_H) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(APP): $(USER_OBJ) $(UTILS_OBJ) $(LOGGING_OBJ) $(CONFIG_OBJ) $(BPF_LOADER_OBJ)
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

$(TUI_APP):
	cd $(TUI_DIR) && CC_x86_64_unknown_linux_musl=musl-gcc cargo build --release --target x86_64-unknown-linux-musl
	cp $(TUI_DIR)/target/x86_64-unknown-linux-musl/release/$(TUI_APP) ./$(TUI_APP).bin

$(INTEL_APP):
	cd $(INTEL_DIR) && CC_x86_64_unknown_linux_musl=musl-gcc \
	    cargo build --release --target x86_64-unknown-linux-musl
	cp $(INTEL_DIR)/target/x86_64-unknown-linux-musl/release/$(INTEL_APP) ./$(INTEL_APP).bin

# Internal: compile skeleton-free modules with current CFLAGS + run unit tests.
# Always called via recursive make with OBJ_DIR and CFLAGS overridden.
_c_tests: $(UTILS_OBJ) $(LOGGING_OBJ) $(CONFIG_OBJ) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -UNDEBUG tests/unit_tests.c \
		$(UTILS_OBJ) $(LOGGING_OBJ) \
		-lbpf -o $(OBJ_DIR)/unit_tests
	$(OBJ_DIR)/unit_tests

# Pass 1: debug flags + Wpedantic + fanalyzer; Rust debug tests
test-debug:
	@echo "=== Pass 1: debug build-test ($(DEBUG_CFLAGS)) ==="
	$(MAKE) CFLAGS="$(DEBUG_CFLAGS)" OBJ_DIR="$(DEBUG_OBJ_DIR)" _c_tests
	cd $(TUI_DIR) && cargo test
	cd $(INTEL_DIR) && cargo test
	@echo "=== Pass 1 PASSED ==="

# Pass 2: release flags; Rust musl release tests
test-release:
	@echo "=== Pass 2: release build-test ($(RELEASE_CFLAGS)) ==="
	$(MAKE) CFLAGS="$(RELEASE_CFLAGS)" OBJ_DIR="$(RELEASE_OBJ_DIR)" _c_tests
	cd $(TUI_DIR) && cargo test --release
	cd $(INTEL_DIR) && cargo test --release
	@echo "=== Pass 2 PASSED ==="

# Pass 3: sanitizer build-test (ASAN + UBSAN)
test-sanitize:
	@echo "=== Pass 3: sanitizer build-test (ASAN+UBSAN) ==="
	$(MAKE) CFLAGS="$(SANITIZE_CFLAGS)" \
	        LDFLAGS="$(LDFLAGS) -fsanitize=address,undefined" \
	        OBJ_DIR="$(SANITIZE_OBJ_DIR)" _c_tests
	@echo "=== Pass 3 PASSED ==="

# Pass 4: ThreadSanitizer — data race detection (mutually exclusive with ASAN)
test-tsan:
	@echo "=== Pass 4: ThreadSanitizer build-test (TSan) ==="
	$(MAKE) CFLAGS="$(TSAN_CFLAGS)" \
	        LDFLAGS="$(LDFLAGS) -fsanitize=thread" \
	        OBJ_DIR="$(TSAN_OBJ_DIR)" _c_tests
	@echo "=== Pass 4 PASSED ==="

# Static analysis and formatting
lint-cppcheck:
	cppcheck --enable=warning,performance,portability \
	         --suppress=missingIncludeSystem \
	         --suppress=intToPointerCast \
	         --suppress=syntaxError:/usr/include/* \
	         -i src/tcp_syn_stop.bpf.c \
	         --error-exitcode=1 --inline-suppr \
	         -I.obj -I/usr/include src/

lint-clippy:
	cd $(TUI_DIR) && cargo clippy --all-targets -- -D warnings
	cd $(INTEL_DIR) && cargo clippy --all-targets -- -D warnings

fmt-check:
	cd $(TUI_DIR) && cargo fmt -- --check
	cd $(INTEL_DIR) && cargo fmt -- --check

compile_commands.json: $(SKEL_H)
	bear -- $(MAKE) -B all
	@echo "compile_commands.json generated"

TIDY_SRCS := $(filter-out $(SRC_DIR)/$(APP).bpf.c, $(wildcard $(SRC_DIR)/*.c))

lint-tidy: compile_commands.json
	clang-tidy --header-filter='^src/' $(TIDY_SRCS)

lint-deny:
	cd $(TUI_DIR) && cargo deny check
	cd $(INTEL_DIR) && cargo deny check

lint: lint-cppcheck lint-clippy lint-tidy lint-deny fmt-check

# Generate a flame graph from a running daemon.
# Usage: sudo make flamegraph PID=<pid>  (or auto-detect via pidof)
flamegraph:
	@PID=$${PID:-$$(pidof tcp_syn_stop)}; \
	if [ -z "$$PID" ]; then echo "Error: tcp_syn_stop not running"; exit 1; fi; \
	echo "Recording 30s of perf data from PID $$PID..."; \
	perf record -F 99 -g --call-graph dwarf -p $$PID -- sleep 30; \
	perf script > $(OBJ_DIR)/perf.out; \
	stackcollapse-perf.pl $(OBJ_DIR)/perf.out | flamegraph.pl > flamegraph.svg; \
	echo "Flamegraph written to flamegraph.svg"

# Preflight: all passes + integration tests — gates make deb
preflight: test-debug test-release test-sanitize test-tsan integration-test

# Legacy alias
test tests: test-release

# Integration Tests (Requires root/sudo and namespaces)
# No dependency on 'all' — build as your user first, then run
# 'sudo make integration-test' without re-compiling as root.
integration-test:
	pytest tests/integration_test.py

# Debian Packaging (via dpkg-buildpackage + debhelper)
deb: all
	@echo "--- Building Debian package with dpkg-buildpackage ---"
	# Substitute version/date/hash/maintainer placeholders
	sed -i 's/__VERSION__/$(VERSION)/g; s/__DATE__/$(BUILD_DATE_RFC2822)/g; s/__HASH__/$(GIT_HASH)/g; s/__MAINTAINER__/$(DEB_MAINTAINER)/g' \
		debian/changelog debian/control debian/copyright
	sed -i 's/__VERSION__/$(VERSION)/g; s/__DATE__/$(BUILD_DATE)/g; s/__MAINTAINER__/$(DEB_MAINTAINER)/g' \
		tcp_syn_stop.8
	dpkg-buildpackage -b -us -uc --no-sign
	# Restore placeholders
	git checkout -- debian/changelog debian/control debian/copyright tcp_syn_stop.8 2>/dev/null || \
		{ sed -i 's/$(VERSION)/__VERSION__/g; s/$(BUILD_DATE_RFC2822)/__DATE__/g; s/$(GIT_HASH)/__HASH__/g; s/$(DEB_MAINTAINER)/__MAINTAINER__/g' debian/changelog debian/control debian/copyright; \
		  sed -i 's/$(VERSION)/__VERSION__/g; s/$(BUILD_DATE)/__DATE__/g; s/$(DEB_MAINTAINER)/__MAINTAINER__/g' tcp_syn_stop.8; }
	# lintian check
	lintian --no-tag-display-limit ../tcp-syn-stop_$(VERSION)_amd64.deb || true
	# Local APT repo
	rm -rf repo/amd64
	mkdir -p repo/amd64 build
	cp ../tcp-syn-stop_$(VERSION)_amd64.deb repo/amd64/
	cd repo && apt-ftparchive packages amd64 > amd64/Packages
	gzip -cn repo/amd64/Packages > repo/amd64/Packages.gz
	apt-ftparchive -o APT::FTPArchive::Release::Codename=amd64 \
		-o APT::FTPArchive::Release::Suite=amd64 release repo/amd64 > repo/amd64/Release
	cd build && sha256sum ../repo/amd64/tcp-syn-stop_$(VERSION)_amd64.deb > SHA256SUMS
	@echo "--- Package: ../tcp-syn-stop_$(VERSION)_amd64.deb ---"

clean:
	rm -rf $(OBJ_DIR) $(APP) $(TUI_APP).bin $(INTEL_APP).bin build/
	if [ -d "$(TUI_DIR)" ]; then cd $(TUI_DIR) && cargo clean || true; fi
	if [ -d "$(INTEL_DIR)" ]; then cd $(INTEL_DIR) && cargo clean || true; fi

-include $(wildcard $(OBJ_DIR)/*.d)

.PHONY: all clean $(TUI_APP) $(INTEL_APP) deb test tests test-debug test-release test-sanitize \
       test-tsan preflight integration-test _c_tests flamegraph \
       lint lint-cppcheck lint-clippy lint-tidy lint-deny fmt-check
