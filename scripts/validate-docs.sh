#!/usr/bin/env bash
# validate-docs.sh — Documentation linting and consistency checks for AnchorKit
#
# Checks:
#   1. Markdown lint (markdownlint-cli)        — heading hierarchy, code blocks, formatting
#   2. Broken internal links                   — relative links between docs
#   3. Heading consistency                     — duplicate or malformed top-level headings
#   4. Command example hygiene                 — bare `cargo`, `make`, and shell commands
#   5. Stale placeholder text                  — TODO / FIXME / TBD / <YOUR_ patterns
#
# Usage:
#   bash scripts/validate-docs.sh              # check all docs
#   bash scripts/validate-docs.sh --fix        # auto-fix markdownlint issues where possible
#   bash scripts/validate-docs.sh --file <f>   # check a single file
#
# Prerequisites (auto-installed if npm is available):
#   npm install -g markdownlint-cli

set -euo pipefail

# ── Colours ─────────────────────────────────────────────────────────────────

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ── Config ───────────────────────────────────────────────────────────────────

DOCS_DIR="${DOCS_DIR:-docs}"
README="README.md"
MARKDOWNLINT_CONFIG=".markdownlint.json"
FIX_MODE=false
SINGLE_FILE=""

ERRORS=0
WARNINGS=0

# ── Argument parsing ─────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
  case "$1" in
    --fix)   FIX_MODE=true ; shift ;;
    --file)  SINGLE_FILE="$2" ; shift 2 ;;
    -h|--help)
      grep '^#' "$0" | head -20 | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "Unknown option: $1" ; exit 1 ;;
  esac
done

# ── Helpers ──────────────────────────────────────────────────────────────────

section() { echo -e "\n${CYAN}${BOLD}── $1 ──${RESET}"; }
pass()    { echo -e "  ${GREEN}✓${RESET} $1"; }
warn()    { echo -e "  ${YELLOW}⚠${RESET}  $1"; WARNINGS=$((WARNINGS + 1)); }
fail()    { echo -e "  ${RED}✗${RESET} $1"; ERRORS=$((ERRORS + 1)); }

# Collect markdown files to check
if [[ -n "$SINGLE_FILE" ]]; then
  MD_FILES=("$SINGLE_FILE")
else
  mapfile -t MD_FILES < <(find "$DOCS_DIR" -name "*.md" | sort)
  [[ -f "$README" ]] && MD_FILES+=("$README")
fi

echo -e "${BOLD}AnchorKit Documentation Lint${RESET}"
echo "Files to check: ${#MD_FILES[@]}"

# ── 1. Markdownlint ──────────────────────────────────────────────────────────

section "Markdown Lint (markdownlint-cli)"

if ! command -v markdownlint &>/dev/null; then
  if command -v npm &>/dev/null; then
    echo "  → markdownlint-cli not found, installing..."
    npm install -g markdownlint-cli --silent
  else
    warn "markdownlint-cli not found and npm unavailable — skipping lint step"
    warn "Install with: npm install -g markdownlint-cli"
  fi
fi

if command -v markdownlint &>/dev/null; then
  LINT_FLAGS=("--config" "$MARKDOWNLINT_CONFIG")
  [[ "$FIX_MODE" == true ]] && LINT_FLAGS+=("--fix")

  LINT_OUTPUT=$(markdownlint "${LINT_FLAGS[@]}" "${MD_FILES[@]}" 2>&1 || true)

  if [[ -z "$LINT_OUTPUT" ]]; then
    pass "All markdown files pass lint checks"
  else
    while IFS= read -r line; do
      fail "$line"
    done <<< "$LINT_OUTPUT"
  fi
fi

# ── 2. Broken internal links ─────────────────────────────────────────────────

section "Broken Internal Links"

# Repository-local link check only — no network access is performed.
# External links (http/https/mailto) are intentionally excluded: validating
# them would require network access and is out of scope for this offline check.
LINK_ERRORS_BEFORE=$ERRORS

for file in "${MD_FILES[@]}"; do
  dir=$(dirname "$file")
  # Extract all markdown link targets: [text](target) or [text](target "title")
  while IFS= read -r link; do
    # Drop an optional link title: (path "title") → path
    link="${link%%[[:space:]]*}"
    # Strip anchor fragments and query strings
    target="${link%%#*}"
    target="${target%%\?*}"
    [[ -z "$target" ]] && continue
    # Skip external URLs (no network access) and mailto links
    [[ "$target" =~ ^https?:// ]] && continue
    [[ "$target" =~ ^mailto: ]]  && continue
    # Skip protocol-relative and other absolute schemes (e.g. ftp:, tel:)
    [[ "$target" =~ ^[a-zA-Z][a-zA-Z0-9+.-]*: ]] && continue
    # Skip pure in-page anchors (already handled by the fragment strip above)
    [[ "$target" =~ ^/ ]] && continue

    resolved="$dir/$target"
    if [[ ! -e "$resolved" ]]; then
      fail "Broken link in ${file}: → ${link}"
    fi
  done < <(grep -oP '\[[^]]*\]\(\K[^)]+' "$file" 2>/dev/null || true)
done

[[ $ERRORS -eq $LINK_ERRORS_BEFORE ]] && pass "No broken internal links found"

# ── 3. Heading consistency ───────────────────────────────────────────────────

section "Heading Consistency"

for file in "${MD_FILES[@]}"; do
  # Each file should have exactly one H1
  h1_count=$(grep -c '^# ' "$file" 2>/dev/null || echo 0)
  if [[ "$h1_count" -eq 0 ]]; then
    warn "$file — missing H1 heading"
  elif [[ "$h1_count" -gt 1 ]]; then
    fail "$file — multiple H1 headings ($h1_count found)"
  fi

  # Detect heading level skips (e.g. H1 → H3 without H2)
  prev_level=0
  line_num=0
  while IFS= read -r line; do
    line_num=$((line_num + 1))
    if [[ "$line" =~ ^(#{1,6})[[:space:]] ]]; then
      level="${#BASH_REMATCH[1]}"
      if [[ $prev_level -gt 0 && $level -gt $((prev_level + 1)) ]]; then
        fail "$file:$line_num — heading level skip H${prev_level} → H${level}"
      fi
      prev_level=$level
    fi
  done < "$file"
done

[[ $ERRORS -eq 0 ]] && pass "Heading structure looks consistent"

# ── 4. Command example hygiene ───────────────────────────────────────────────

section "Command Example Hygiene"

# Commands inside fenced code blocks should use the canonical tool, not aliases
# Detect `$ cargo` used outside a code block (people sometimes prefix with $)
for file in "${MD_FILES[@]}"; do
  # Warn on `$ command` patterns — the $ prompt should not appear in copy-pasteable examples
  if grep -nP '^\s*\$\s+(cargo|make|bash|sh)\b' "$file" &>/dev/null; then
    matches=$(grep -nP '^\s*\$\s+(cargo|make|bash|sh)\b' "$file")
    while IFS= read -r m; do
      warn "$file — shell prompt '\$' in command example (remove for clean copy-paste): $m"
    done <<< "$matches"
  fi

  # Detect unfenced shell commands outside code blocks (very rough heuristic)
  # Flag lines that look like commands but aren't inside ``` blocks
  in_fence=false
  line_num=0
  while IFS= read -r line; do
    line_num=$((line_num + 1))
    if [[ "$line" =~ ^\`\`\` ]]; then
      $in_fence && in_fence=false || in_fence=true
      continue
    fi
    if ! $in_fence; then
      if [[ "$line" =~ ^cargo[[:space:]]|^make[[:space:]]|^rustup[[:space:]] ]]; then
        warn "$file:$line_num — command outside fenced block: ${line:0:60}"
      fi
    fi
  done < "$file"
done

[[ $WARNINGS -eq 0 ]] && pass "Command examples look well-formed"

# ── 5. Stale placeholder text ────────────────────────────────────────────────

section "Stale Placeholder Text"

PLACEHOLDER_PATTERNS=(
  'TODO[^:]*:'
  'FIXME[^:]*:'
  '\bTBD\b'
  '<YOUR_[A-Z_]+>'
  '<INSERT'
  '\[PLACEHOLDER\]'
)

for file in "${MD_FILES[@]}"; do
  for pattern in "${PLACEHOLDER_PATTERNS[@]}"; do
    matches=$(grep -nP "$pattern" "$file" 2>/dev/null || true)
    if [[ -n "$matches" ]]; then
      while IFS= read -r m; do
        warn "$file — placeholder/stale text: $m"
      done <<< "$matches"
    fi
  done
done

[[ $WARNINGS -eq 0 ]] && pass "No stale placeholder text found"

# ── Summary ──────────────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}── Summary ──────────────────────────────────────────────────────────${RESET}"
echo -e "  Files checked : ${#MD_FILES[@]}"
echo -e "  Errors        : ${ERRORS}"
echo -e "  Warnings      : ${WARNINGS}"

if [[ $ERRORS -gt 0 ]]; then
  echo -e "\n${RED}${BOLD}✗ Documentation lint FAILED ($ERRORS error(s))${RESET}"
  exit 1
elif [[ $WARNINGS -gt 0 ]]; then
  echo -e "\n${YELLOW}${BOLD}⚠  Documentation lint passed with warnings ($WARNINGS warning(s))${RESET}"
  exit 0
else
  echo -e "\n${GREEN}${BOLD}✓ Documentation lint passed${RESET}"
  exit 0
fi
