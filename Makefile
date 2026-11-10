CARGO ?= $(shell command -v cargo 2>/dev/null || echo $(HOME)/.cargo/bin/cargo)
FEATURES ?= default
RUSTFLAGS ?=
SCCACHE := $(shell command -v sccache 2>/dev/null || { [ -x "$(HOME)/.local/bin/sccache" ] && echo "$(HOME)/.local/bin/sccache"; })
ifneq ($(SCCACHE),)
export RUSTC_WRAPPER := $(SCCACHE)
export SCCACHE_DIR ?= $(HOME)/Library/Caches/sccache
endif

# ort-sys (via gaze-recognizers) links ONNX Runtime. Prefer an explicit
# ORT_LIB_PATH; otherwise auto-detect a common local libonnxruntime dylib so
# offline builds do not try to download binaries.
ORT_LIB_CANDIDATES := /usr/local/opt/onnxruntime/lib /opt/homebrew/opt/onnxruntime/lib $(HOME)/hc/resources/basemind
ORT_LIB_PATH ?= $(shell for d in $(ORT_LIB_CANDIDATES); do if ls "$$d"/libonnxruntime*.dylib >/dev/null 2>&1; then printf '%s' "$$d"; break; fi; done)
ifneq ($(ORT_LIB_PATH),)
export ORT_LIB_PATH
export ORT_PREFER_DYNAMIC_LINK := 1
export DYLD_LIBRARY_PATH := $(ORT_LIB_PATH):$(DYLD_LIBRARY_PATH)
export DYLD_FALLBACK_LIBRARY_PATH := $(ORT_LIB_PATH):$(DYLD_FALLBACK_LIBRARY_PATH)
endif

.PHONY: help fmt-check fmt check-fast build-fast lint-fast check-all lint-all test-fast test-corpus ci-fast ci-all ci-full dev dev-http

help:
	@printf '%s\n' \
		'make fmt-check   Check Rust formatting' \
		'make fmt         Format Rust sources' \
		'make check-fast  Fast library/binary check' \
		'make build-fast  Fast library/binary build' \
		'make lint-fast   Fast clippy lint' \
		'make check-all   Check all targets, including tests' \
		'make lint-all    Lint all targets, including tests' \
		'make test-fast   Fast test run using the ci profile' \
		'make test-corpus Heavy format/corpus tests (xberg-formats)' \
		'make ci-fast     Fast local verification loop' \
		'make ci-all      All-target checks plus fast tests' \
		'make ci-full     Full, slower strict verification' \
		'make dev         Start stdio MCP server' \
		'make dev-http    Start HTTP MCP server on 127.0.0.1:8080'

fmt-check:
	$(CARGO) fmt --all --check

fmt:
	$(CARGO) fmt --all

check-fast:
	CARGO_TERM_COLOR=never RUSTFLAGS="$(RUSTFLAGS)" $(CARGO) check --features $(FEATURES) --message-format=short

build-fast:
	CARGO_TERM_COLOR=never RUSTFLAGS="$(RUSTFLAGS)" $(CARGO) build --features $(FEATURES)

lint-fast:
	@if $(CARGO) clippy --help 2>&1 | grep -q -- '--no-deps'; then \
		CARGO_TERM_COLOR=never RUSTFLAGS="$(RUSTFLAGS)" $(CARGO) clippy --no-deps --features $(FEATURES) -- -D warnings; \
	else \
		CARGO_TERM_COLOR=never RUSTFLAGS="$(RUSTFLAGS)" $(CARGO) clippy --features $(FEATURES) -- -D warnings; \
	fi

check-all:
	CARGO_TERM_COLOR=never RUSTFLAGS="$(RUSTFLAGS)" $(CARGO) check --all-targets --features $(FEATURES)

lint-all:
	@if $(CARGO) clippy --help 2>&1 | grep -q -- '--no-deps'; then \
		CARGO_TERM_COLOR=never RUSTFLAGS="$(RUSTFLAGS)" $(CARGO) clippy --all-targets --no-deps --features $(FEATURES) -- -D warnings; \
	else \
		CARGO_TERM_COLOR=never RUSTFLAGS="$(RUSTFLAGS)" $(CARGO) clippy --all-targets --features $(FEATURES) -- -D warnings; \
	fi

test-fast:
	@if $(CARGO) test --help 2>&1 | grep -q -- '--profile'; then \
		CARGO_TERM_COLOR=never CARGO_PROFILE_CI_DEBUG=0 CARGO_PROFILE_CI_INCREMENTAL=true RUSTFLAGS="$(RUSTFLAGS)" $(CARGO) test --all --features $(FEATURES) --profile ci --message-format=short; \
	else \
		CARGO_TERM_COLOR=never CARGO_PROFILE_CI_DEBUG=0 CARGO_PROFILE_CI_INCREMENTAL=true RUSTFLAGS="$(RUSTFLAGS)" $(CARGO) test --all --features $(FEATURES) --message-format=short; \
	fi

test-corpus:
	CARGO_TERM_COLOR=never CARGO_PROFILE_CI_DEBUG=0 CARGO_PROFILE_CI_INCREMENTAL=true RUSTFLAGS="$(RUSTFLAGS)" $(CARGO) test --all --features xberg-formats --profile ci --test corpus

ci-fast: fmt-check check-fast lint-fast test-fast

ci-all: fmt-check check-all lint-all test-fast

dev:
	$(CARGO) run -- mcp --transport stdio

dev-http:
	$(CARGO) run -- mcp --transport http --http-addr 127.0.0.1:8080

# Full verification mirrors the strict CI commands and is intentionally slower.
ci-full:
	$(CARGO) fmt --all --check
	$(CARGO) clippy --all-targets --all-features -- -D warnings
	$(CARGO) test --all --all-features
