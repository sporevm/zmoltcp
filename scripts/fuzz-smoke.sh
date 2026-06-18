#!/usr/bin/env bash
set -euo pipefail

for attempt in 1 2 3; do
  log_file="$(mktemp "${TMPDIR:-/tmp}/zmoltcp-fuzz.XXXXXX")"
  cache_dir="$(mktemp -d "${TMPDIR:-/tmp}/zmoltcp-fuzz-cache.XXXXXX")"

  export ZIG_LOCAL_CACHE_DIR="$cache_dir/local"
  export ZIG_GLOBAL_CACHE_DIR="$cache_dir/global"
  mkdir -p "$ZIG_LOCAL_CACHE_DIR" "$ZIG_GLOBAL_CACHE_DIR"

  if zig build fuzz --fuzz=10K --test-timeout 30s --summary all 2>&1 | tee "$log_file"; then
    build_ok=1
  else
    build_ok=0
  fi

  if [ "$build_ok" -eq 1 ] && ! grep -Eq 'run test failure|terminated with signal|input saved to|panic:|failed with error' "$log_file"; then
    rm -f "$log_file"
    rm -rf "$cache_dir"
    exit 0
  fi

  if grep -q 'corrupted coverage file' "$log_file"; then
    if [ "$attempt" -lt 3 ]; then
      echo "fuzz smoke hit Zig coverage cache corruption; retrying with a fresh cache" >&2
      rm -f "$log_file"
      rm -rf "$cache_dir"
      continue
    fi

    if [ "${ZIG_FUZZ_ALLOW_COVERAGE_FALLBACK:-0}" = "1" ]; then
      echo "fuzz smoke hit repeated Zig coverage cache corruption; running non-instrumented fuzz target smoke" >&2
      rm -f "$log_file"
      rm -rf "$cache_dir"

      log_file="$(mktemp "${TMPDIR:-/tmp}/zmoltcp-fuzz.XXXXXX")"
      cache_dir="$(mktemp -d "${TMPDIR:-/tmp}/zmoltcp-fuzz-cache.XXXXXX")"
      export ZIG_LOCAL_CACHE_DIR="$cache_dir/local"
      export ZIG_GLOBAL_CACHE_DIR="$cache_dir/global"
      mkdir -p "$ZIG_LOCAL_CACHE_DIR" "$ZIG_GLOBAL_CACHE_DIR"

      if zig build fuzz --summary all 2>&1 | tee "$log_file" &&
        ! grep -Eq 'run test failure|terminated with signal|input saved to|panic:|failed with error' "$log_file"; then
        rm -f "$log_file"
        rm -rf "$cache_dir"
        exit 0
      fi
    fi
  fi

  if grep -Eq 'run test failure|terminated with signal|input saved to|panic:|failed with error' "$log_file"; then
    echo "fuzz smoke output contained failure markers" >&2
  fi
  echo "fuzz log preserved at $log_file" >&2
  echo "fuzz cache preserved at $cache_dir" >&2
  exit 1
done
