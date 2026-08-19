#!/usr/bin/env bash
# Explicit opt-in runner for a real repository-local enrollment experiment.
# It installs nothing and records logical CV command evidence from the
# interposer.  This is not a USB bus trace.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
LOCAL="$REPO/.local-test"
EXPERIMENT="$LOCAL/enrollment-0x89"
TARGET="$LOCAL/tod-drivers/libfprint-2-tod-1-broadcom-5833.probe.so"
PRELOAD="$EXPERIMENT/libcv2-enrollment-0x89-rearm.so"
HARNESS="$EXPERIMENT/cv_tod_enrollment_experiment"
CONFIRMED=no
UPDATE_POLICY=legacy-repeat
BOUNDARY_MODE_COUNT=0
TRACE_METADATA=0
CHILD_PID=""

usage() {
    cat <<'EOF'
Usage:
  tools/run_local_enrollment_0x89_test.sh --confirm-real-enrollment \
    [--fresh-boundary|--fresh-rearm-boundary|--zero-input-boundary] \
    [--trace-update-metadata]

WARNING: this exercises real enrollment. If all stages succeed, the
ControlVault driver may commit a fingerprint template inside the device.
Nothing is installed and no PAM, GNOME, udev, systemd, or system libfprint
configuration is changed.

--fresh-boundary sends one update per fresh capture, preserves native 0x59,
and converts a native nonzero completion into a fatal cleanup before the
unchanged state machine can enter generic commit.

--fresh-rearm-boundary retains those boundaries and sends one native 0x8a
after each accepted incomplete update. It stops on the fourth incomplete
acceptance rather than allowing another capture.

--zero-input-boundary retains the fresh-rearm boundaries and changes only the
required 20-byte native UpdateEnrollment input to one stable all-zero buffer.
It never reads or logs the replaced source bytes, permits at most 24 native
updates, and still blocks commit on native completion.

--trace-update-metadata records only call-level lengths, pointer/content
relations, and zero/changed classifications. It never prints pointer addresses
or buffer bytes.
EOF
}

while (($#)); do
    case "$1" in
        --confirm-real-enrollment)
            CONFIRMED=yes
            shift
            ;;
        --fresh-boundary)
            UPDATE_POLICY=fresh-stop-before-commit
            BOUNDARY_MODE_COUNT=$((BOUNDARY_MODE_COUNT + 1))
            shift
            ;;
        --fresh-rearm-boundary)
            UPDATE_POLICY=fresh-rearm-stop-before-commit
            BOUNDARY_MODE_COUNT=$((BOUNDARY_MODE_COUNT + 1))
            shift
            ;;
        --zero-input-boundary)
            UPDATE_POLICY=zero-input-fresh-rearm-stop-before-commit
            BOUNDARY_MODE_COUNT=$((BOUNDARY_MODE_COUNT + 1))
            shift
            ;;
        --trace-update-metadata)
            TRACE_METADATA=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if ((BOUNDARY_MODE_COUNT > 1)); then
    echo "multiple enrollment boundary modes selected; refusing ambiguity" >&2
    exit 2
fi

if [[ "$CONFIRMED" != yes ]]; then
    usage >&2
    echo "refusing to touch hardware without the explicit confirmation flag" >&2
    exit 2
fi

"$REPO/tools/build_enrollment_0x89_experiment.sh"
for required in "$TARGET" "$PRELOAD" "$HARNESS"; do
    if [[ ! -e "$required" ]]; then
        echo "repository-local test prerequisite missing: $required" >&2
        exit 1
    fi
done

TARGET_CANONICAL="$(realpath -e "$TARGET")"

VALIDATION="$(
    python3 "$REPO/tools/enrollment_0x89_target.py" \
        "$TARGET" --preload "$PRELOAD"
)"
EXPERIMENT_PRELOAD="$(
    sed -n 's/^validated_LD_PRELOAD=//p' <<<"$VALIDATION"
)"
if [[ -z "$EXPERIMENT_PRELOAD" ]]; then
    echo "validator did not produce an LD_PRELOAD value" >&2
    exit 1
fi

export LD_LIBRARY_PATH="$LOCAL/libfprint-build/libfprint/tod:$LOCAL/libfprint-build/libfprint"
export FP_TOD_DRIVERS_DIR="$LOCAL/tod-drivers"
export FP_DRIVERS_ALLOWLIST="broadcom"
export G_MESSAGES_DEBUG="all"
export CV2_0X89_TARGET_PATH="$TARGET_CANONICAL"
export CV2_ENROLLMENT_UPDATE_POLICY="$UPDATE_POLICY"
export CV2_UPDATE_METADATA_TRACE="$TRACE_METADATA"

mkdir -p "$REPO/test-results"
STAMP="$(date --iso-8601=seconds | tr ':' '-')"
if [[ "$UPDATE_POLICY" == zero-input-fresh-rearm-stop-before-commit ]]; then
    LOG="$REPO/test-results/enrollment-zero-input-boundary-$STAMP.log"
elif [[ "$UPDATE_POLICY" == fresh-rearm-stop-before-commit ]]; then
    LOG="$REPO/test-results/enrollment-fresh-rearm-boundary-$STAMP.log"
elif [[ "$UPDATE_POLICY" == fresh-stop-before-commit ]]; then
    LOG="$REPO/test-results/enrollment-fresh-boundary-$STAMP.log"
else
    LOG="$REPO/test-results/enrollment-0x59-single-update-retry-$STAMP.log"
fi

cleanup() {
    local signal="${1:-TERM}"
    if [[ -n "$CHILD_PID" ]] && kill -0 "$CHILD_PID" 2>/dev/null; then
        echo "forwarding $signal to enrollment harness" | tee -a "$LOG"
        kill "-$signal" "$CHILD_PID" 2>/dev/null || true
        wait "$CHILD_PID" || true
    fi
}
trap 'cleanup INT; exit 130' INT
trap 'cleanup TERM; exit 143' TERM

{
    echo "evidence_timestamp=$(date --iso-8601=seconds)"
    echo "$VALIDATION"
    echo "evidence_scope=repository-local logical command logging; not USBPcap"
    if [[ "$UPDATE_POLICY" == zero-input-fresh-rearm-stop-before-commit ]]; then
        echo "experiment=stable zero 20-byte update input with accepted-incomplete re-arm"
        echo "changed_native_argument=20-byte UpdateEnrollment input only"
        echo "source_input_bytes_read_or_logged=no"
        echo "same_update_retry=disabled"
        echo "accepted_incomplete_rearm=one native 0x8A before next capture"
        echo "accepted_update_limit=4"
        echo "total_native_update_limit=24"
        echo "native_completion_policy=return fatal status to existing cleanup"
    elif [[ "$UPDATE_POLICY" == fresh-rearm-stop-before-commit ]]; then
        echo "experiment=fresh capture per update with accepted-incomplete re-arm"
        echo "same_update_retry=disabled"
        echo "accepted_incomplete_rearm=one native 0x8A before next capture"
        echo "accepted_update_limit=4"
        echo "native_completion_policy=return fatal status to existing cleanup"
    elif [[ "$UPDATE_POLICY" == fresh-stop-before-commit ]]; then
        echo "experiment=fresh capture per update; stop before native completion commit"
        echo "same_update_retry=disabled"
        echo "native_completion_policy=return fatal status to existing cleanup"
    else
        echo "experiment=bounded single repeated UpdateEnrollment after native 0x59"
        echo "retry_limit=one additional 0x6C call per intercepted invocation"
    fi
    echo "update_policy=$CV2_ENROLLMENT_UPDATE_POLICY"
    echo "update_metadata_trace=$CV2_UPDATE_METADATA_TRACE"
    echo "interposer_target=$CV2_0X89_TARGET_PATH"
    echo "warning=successful enrollment may commit a device template"
} | tee "$LOG"

set +e
LD_PRELOAD="$EXPERIMENT_PRELOAD" \
    "$HARNESS" > >(tee -a "$LOG") 2>&1 &
CHILD_PID=$!
wait "$CHILD_PID"
STATUS=$?
CHILD_PID=""
set -e

echo "harness_exit_status=$STATUS" | tee -a "$LOG"
echo "evidence_file=$LOG"
exit "$STATUS"
