#!/usr/bin/env bash
# Explicit opt-in runner for one capture-only, metadata-only hardware probe.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
LOCAL="$REPO/.local-test"
PROBE="$LOCAL/capture-result-probe"
TARGET="$LOCAL/tod-drivers/libfprint-2-tod-1-broadcom-5833.probe.so"
PRELOAD="$PROBE/libcv2-capture-result-probe.so"
HARNESS="$PROBE/cv_tod_capture_result_experiment"
CONFIRMED=no
CHILD_PID=""

usage() {
    cat <<'EOF'
Usage: tools/run_capture_get_result_probe.sh --confirm-capture-only

This performs one normal fingerprint capture and one native
CaptureGetResult(selector=1) call. It logs only status and returned length.
The private result buffer is wiped immediately. UpdateEnrollment is never
forwarded; CreateTemplate and CommitEnrollment are never resolved or called.
Nothing is installed and no service or system configuration is changed.
EOF
}

while (($#)); do
    case "$1" in
        --confirm-capture-only) CONFIRMED=yes ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

if [[ "$CONFIRMED" != yes ]]; then
    usage >&2
    echo "refusing hardware access without explicit confirmation" >&2
    exit 2
fi

for command in lsusb pgrep realpath; do
    command -v "$command" >/dev/null || {
        echo "missing runtime command: $command" >&2
        exit 1
    }
done
if ! lsusb -d 0a5c:5833 | grep -q '0a5c:5833'; then
    echo "supported 0a5c:5833 device is not present" >&2
    exit 1
fi
if pgrep -x fprintd >/dev/null; then
    echo "fprintd is running; stop it before this exclusive probe" >&2
    exit 1
fi
if command -v systemctl >/dev/null &&
   systemctl is-active --quiet fprintd.service 2>/dev/null; then
    echo "fprintd.service is active; stop it before this exclusive probe" >&2
    exit 1
fi

"$REPO/tools/build_capture_get_result_probe.sh"
for required in "$TARGET" "$PRELOAD" "$HARNESS"; do
    [[ -e "$required" ]] || {
        echo "repository-local prerequisite missing: $required" >&2
        exit 1
    }
done

VALIDATION="$(python3 "$REPO/tools/enrollment_0x89_target.py" \
    "$TARGET" --preload "$PRELOAD")"
EXPERIMENT_PRELOAD="$(sed -n 's/^validated_LD_PRELOAD=//p' <<<"$VALIDATION")"
[[ -n "$EXPERIMENT_PRELOAD" ]] || {
    echo "validator did not produce LD_PRELOAD" >&2
    exit 1
}

export LD_LIBRARY_PATH="$LOCAL/libfprint-build/libfprint/tod:$LOCAL/libfprint-build/libfprint"
export FP_TOD_DRIVERS_DIR="$LOCAL/tod-drivers"
export FP_DRIVERS_ALLOWLIST="broadcom"
export CV2_CAPTURE_RESULT_TARGET_PATH="$(realpath -e "$TARGET")"

mkdir -p "$REPO/test-results"
STAMP="$(date --iso-8601=seconds | tr ':' '-')"
LOG="$REPO/test-results/capture-get-result-$STAMP.log"

cleanup() {
    local signal="${1:-TERM}"
    if [[ -n "$CHILD_PID" ]] && kill -0 "$CHILD_PID" 2>/dev/null; then
        kill "-$signal" "$CHILD_PID" 2>/dev/null || true
        wait "$CHILD_PID" || true
    fi
}
trap 'cleanup INT; exit 130' INT
trap 'cleanup TERM; exit 143' TERM

{
    echo "evidence_timestamp=$(date --iso-8601=seconds)"
    echo "$VALIDATION"
    echo "experiment=capture-only CaptureGetResult selector 1"
    echo "initial_capacity=94208"
    echo "payload_logging=disabled"
    echo "payload_retention=private buffer wiped before free"
    echo "UpdateEnrollment_forwarding=disabled"
    echo "CreateTemplate=disabled"
    echo "CommitEnrollment=disabled"
    echo "system_changes=none"
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
