#!/usr/bin/env bash
# =============================================================================
#  Cyber Sentinel XDR — Model Evaluation Runner  (Linux / macOS / WSL)
#  Usage: bash run_evaluation.sh
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

SEP="═══════════════════════════════════════════════════════════════════════"
OK="  ✓ "
WARN="  ⚠️  "
ERR="  ❌  "

echo ""
echo "$SEP"
echo "   CYBER SENTINEL XDR — Model Evaluation Runner"
echo "   Linux / macOS / WSL"
echo "$SEP"
echo ""

# ─────────────────────── Python check ────────────────────────────────────────

PY=""
for candidate in python3 python; do
    if command -v "$candidate" &>/dev/null; then
        VER=$("$candidate" --version 2>&1 | head -1)
        echo "${OK}Found: $VER  ($candidate)"
        PY="$candidate"
        break
    fi
done

if [[ -z "$PY" ]]; then
    echo "${ERR}Python not found."
    echo "     Install from https://python.org or run:"
    echo "       sudo apt-get install python3   # Ubuntu/Debian"
    echo "       brew install python            # macOS"
    exit 1
fi

# ─────────────────────── pip check ───────────────────────────────────────────

PIP=""
for pip_cmd in pip3 pip "$PY -m pip"; do
    if $pip_cmd --version &>/dev/null 2>&1; then
        PIP="$pip_cmd"
        break
    fi
done

if [[ -z "$PIP" ]]; then
    echo "${WARN}pip not found. Trying to bootstrap..."
    $PY -m ensurepip --upgrade 2>/dev/null || true
    PIP="$PY -m pip"
fi

echo "${OK}Using pip: $PIP"

# ─────────────────────── install dependencies ────────────────────────────────

echo ""
echo "  📦  Installing required packages..."
echo "     (scikit-learn, numpy, pandas, matplotlib, seaborn)"

$PIP install --quiet --upgrade \
    scikit-learn numpy pandas matplotlib seaborn 2>&1 | tail -3

if [[ $? -ne 0 ]]; then
    echo "${WARN}Some packages may not have installed cleanly."
    echo "     Continuing anyway — evaluation will skip optional dependencies."
else
    echo "${OK}Dependencies installed / up-to-date"
fi

# ─────────────────────── locate script ───────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EVAL_SCRIPT="$SCRIPT_DIR/evaluate_all_models.py"

if [[ ! -f "$EVAL_SCRIPT" ]]; then
    echo "${ERR}evaluate_all_models.py not found in $SCRIPT_DIR"
    echo "     Make sure all three files are in the same directory."
    exit 1
fi

echo "${OK}Found: $EVAL_SCRIPT"

# ─────────────────────── run evaluation ──────────────────────────────────────

echo ""
echo "  🚀  Running model evaluation..."
echo "     (This may take 15-60 seconds depending on your machine)"
echo ""

cd "$SCRIPT_DIR"
$PY "$EVAL_SCRIPT"
EXIT_CODE=$?

echo ""

if [[ $EXIT_CODE -ne 0 ]]; then
    echo "${ERR}Evaluation exited with code $EXIT_CODE"
    echo "     Check the error messages above."
    exit $EXIT_CODE
fi

# ─────────────────────── verify outputs ──────────────────────────────────────

REPORT=$(ls "$SCRIPT_DIR"/model_evaluation_report*.txt 2>/dev/null | sort | tail -1)
JSON="$SCRIPT_DIR/model_evaluation_metrics.json"

echo "  ─────────────────────────────────────────────────────────────"
echo "  OUTPUT FILES"
echo "  ─────────────────────────────────────────────────────────────"

if [[ -f "$REPORT" ]]; then
    echo "${OK}Report   : $REPORT"
else
    echo "${WARN}Report not found — check errors above"
fi

if [[ -f "$JSON" ]]; then
    echo "${OK}Metrics  : $JSON"
fi

PLOTS_DIR="$SCRIPT_DIR/evaluation_plots"
if [[ -d "$PLOTS_DIR" ]]; then
    N_PLOTS=$(find "$PLOTS_DIR" -name "*.png" 2>/dev/null | wc -l | tr -d ' ')
    echo "${OK}Plots    : $PLOTS_DIR  ($N_PLOTS PNG files)"
fi

echo ""

# ─────────────────────── open report ─────────────────────────────────────────

if [[ -n "$REPORT" ]]; then
    echo "  Opening report..."
    if command -v xdg-open &>/dev/null; then
        xdg-open "$REPORT" &
    elif command -v open &>/dev/null; then
        open "$REPORT"
    elif command -v gedit &>/dev/null; then
        gedit "$REPORT" &
    elif command -v nano &>/dev/null; then
        echo "     (use: nano \"$REPORT\")"
    else
        echo "     Open manually: $REPORT"
    fi
fi

echo "$SEP"
echo "  Evaluation complete! Review the report for teacher presentation tips."
echo "$SEP"
echo ""
