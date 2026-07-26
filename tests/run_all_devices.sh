#!/usr/bin/env bash
# Build the app and run the functional tests on every device in ledger_app.toml.
#
#   ./tests/run_all_devices.sh            # verify against the committed snapshots
#   ./tests/run_all_devices.sh --golden   # regenerate the snapshots first
#
# Expects: docker with the ledger-app-builder image, and speculos + ragger on
# PATH (pip install "ragger[speculos]").
set -u
cd "$(dirname "$0")/.."

BUILDER=${BUILDER:-ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-lite:latest}
PYTEST=${PYTEST:-pytest}
GOLDEN=""
[ "${1:-}" = "--golden" ] && GOLDEN="--golden_run"

# ledger_app.toml device name -> (SDK variable, pytest --device value)
DEVICES="stax:/opt/stax-secure-sdk flex:/opt/flex-secure-sdk apex_p:/opt/apex-secure-sdk"

rc=0
for entry in $DEVICES; do
  device=${entry%%:*}
  sdk=${entry##*:}
  echo "═══ $device ═══"
  docker run --rm -e BOLOS_SDK="$sdk" -v "$PWD":/app "$BUILDER" \
    bash -c 'cd /app && make -j' >/dev/null 2>&1 || { echo "  BUILD FAILED"; rc=1; continue; }
  if $PYTEST tests/standalone/ -q --device "$device" $GOLDEN 2>&1 | tail -3; then
    :
  else
    rc=1
  fi
done
exit $rc
