CARGO ?= $(shell command -v cargo 2>/dev/null || echo $(HOME)/.cargo/bin/cargo)
FEATURES ?= default
RUSTFLAGS ?=
SCCACHE := $(shell command -v sccache 2>/dev/null || { [ -x "$(HOME)/.local/bin/sccache" ] && echo "$(HOME)/.local/bin/sccache"; })
ifneq ($(SCCACHE),)
export RUSTC_WRAPPER := $(SCCACHE)
export SCCACHE_DIR ?= $(HOME)/Library/Caches/sccache
endif

.PHONY: help fmt-check fmt check-fast build-fast lint-fast test-fast ci-fast ci-full

help:
	@printf '%s\n' \
		'make fmt-check   Check Rust formatting' \
		'make fmt         Format Rust sources' \
		'make check-fast  Fast all-targets check' \
		'make build-fast  Fast all-targets build' \
		'make lint-fast   Fast clippy lint' \
		'make test-fast   Fast test run using the ci profile' \
		'make ci-fast     Fast local verification loop' \
		'make ci-full     Full, slower strict verification'

fmt-check:
	$(CARGO) fmt --all --check

fmt:
	$(CARGO) fmt --all

check-fast:
	CARGO_TERM_COLOR=never RUSTFLAGS="$(RUSTFLAGS)" $(CARGO) check --all-targets --features $(FEATURES) --message-format=short

build-fast:
	CARGO_TERM_COLOR=never RUSTFLAGS="$(RUSTFLAGS)" $(CARGO) build --all-targets --features $(FEATURES)

lint-fast:
	@if $(CARGO) clippy --help 2>&1 | grep -q -- '--no-deps'; then \
		CARGO_TERM_COLOR=never RUSTFLAGS="$(RUSTFLAGS)" $(CARGO) clippy --all-targets --features $(FEATURES) --no-deps -- -D warnings; \
	else \
		CARGO_TERM_COLOR=never RUSTFLAGS="$(RUSTFLAGS)" $(CARGO) clippy --all-targets --features $(FEATURES) -- -D warnings; \
	fi

test-fast:
	@if $(CARGO) test --help 2>&1 | grep -q -- '--profile'; then \
		CARGO_TERM_COLOR=never CARGO_PROFILE_CI_DEBUG=0 CARGO_PROFILE_CI_INCREMENTAL=true RUSTFLAGS="$(RUSTFLAGS)" $(CARGO) test --all --features $(FEATURES) --profile ci --message-format=short; \
	else \
		CARGO_TERM_COLOR=never CARGO_PROFILE_CI_DEBUG=0 CARGO_PROFILE_CI_INCREMENTAL=true RUSTFLAGS="$(RUSTFLAGS)" $(CARGO) test --all --features $(FEATURES) --message-format=short; \
	fi

ci-fast: fmt-check check-fast lint-fast test-fast

# Full verification mirrors the strict CI commands and is intentionally slower.
ci-full:
	$(CARGO) fmt --all --check
	$(CARGO) clippy --all-targets --all-features -- -D warnings
	$(CARGO) test --all --all-features
