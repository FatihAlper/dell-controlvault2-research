#!/usr/bin/env bash
# Build the repository-local 0x89 enrollment interposer.  The target plugin is
# validated and read only; no system path is touched.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
LOCAL="$REPO/.local-test/enrollment-0x89"
TARGET="$REPO/prebuilt/libfprint-2-tod-1-broadcom-5833.probe.so"
OUTPUT="$LOCAL/libcv2-enrollment-0x89-rearm.so"
TOD_BUILD="$REPO/.local-test/libfprint-build"
HARNESS="$LOCAL/cv_tod_enrollment_experiment"

for command in gcc python3 sha256sum; do
    if ! command -v "$command" >/dev/null; then
        echo "missing build command: $command" >&2
        exit 1
    fi
done

BEFORE="$(sha256sum "$TARGET" | awk '{print $1}')"
python3 "$REPO/tools/enrollment_0x89_target.py" "$TARGET"

mkdir -p "$LOCAL"
gcc -std=c11 -fPIC -shared -Wall -Wextra -Werror \
    "$REPO/tools/enrollment_0x89_rearm_preload.c" \
    -Wl,-z,defs -Wl,-z,relro -Wl,-z,now \
    -ldl -pthread -o "$OUTPUT"

if [[ -f "$TOD_BUILD/meson-uninstalled/libfprint-2-uninstalled.pc" ]]; then
    export PKG_CONFIG_PATH="$TOD_BUILD/meson-uninstalled"
    # pkg-config returns the compiler/linker flags for the pinned local build.
    # shellcheck disable=SC2046
    gcc -std=c11 -Wall -Wextra -Werror \
        "$REPO/tools/cv_tod_enrollment_experiment.c" \
        -o "$HARNESS" \
        $(pkg-config --cflags --libs libfprint-2-uninstalled)
    echo "hardware_harness=$HARNESS"
else
    echo "hardware_harness=not-built (local libfprint TOD build unavailable)"
fi

AFTER="$(sha256sum "$TARGET" | awk '{print $1}')"
if [[ "$BEFORE" != "$AFTER" ]]; then
    echo "target artifact changed during build; refusing experiment" >&2
    exit 1
fi

echo "experiment_artifact=$OUTPUT"
echo "target_sha256_before=$BEFORE"
echo "target_sha256_after=$AFTER"
echo "target_write_performed=no"
