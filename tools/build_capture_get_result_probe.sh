#!/usr/bin/env bash
# Build only repository-local artifacts for the capture-only probe.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
LOCAL="$REPO/.local-test/capture-result-probe"
TARGET="$REPO/prebuilt/libfprint-2-tod-1-broadcom-5833.probe.so"
OUTPUT="$LOCAL/libcv2-capture-result-probe.so"
HARNESS="$LOCAL/cv_tod_capture_result_experiment"
TOD_BUILD="$REPO/.local-test/libfprint-build"

for command in gcc python3 sha256sum; do
    command -v "$command" >/dev/null || {
        echo "missing build command: $command" >&2
        exit 1
    }
done

BEFORE="$(sha256sum "$TARGET" | awk '{print $1}')"
python3 "$REPO/tools/enrollment_0x89_target.py" "$TARGET"
mkdir -p "$LOCAL"
gcc -std=c11 -fPIC -shared -Wall -Wextra -Werror \
    "$REPO/tools/capture_get_result_probe_preload.c" \
    -Wl,-z,defs -Wl,-z,relro -Wl,-z,now \
    -ldl -pthread -o "$OUTPUT"

if [[ ! -f "$TOD_BUILD/meson-uninstalled/libfprint-2-uninstalled.pc" ]]; then
    echo "local libfprint TOD build unavailable" >&2
    exit 1
fi
export PKG_CONFIG_PATH="$TOD_BUILD/meson-uninstalled"
# shellcheck disable=SC2046
gcc -std=c11 -Wall -Wextra -Werror \
    "$REPO/tools/cv_tod_capture_result_experiment.c" \
    -o "$HARNESS" \
    $(pkg-config --cflags --libs libfprint-2-uninstalled)

AFTER="$(sha256sum "$TARGET" | awk '{print $1}')"
[[ "$BEFORE" == "$AFTER" ]] || {
    echo "target artifact changed during build" >&2
    exit 1
}
echo "probe_artifact=$OUTPUT"
echo "hardware_harness=$HARNESS"
echo "target_sha256_before=$BEFORE"
echo "target_sha256_after=$AFTER"
echo "target_write_performed=no"
