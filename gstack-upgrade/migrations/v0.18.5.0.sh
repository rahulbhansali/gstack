#!/usr/bin/env bash
# Migration: v0.18.5.0 — Remove stale /checkpoint skill installs
#
# Claude Code ships /checkpoint as a native alias for /rewind, which was
# shadowing the gstack checkpoint skill. The skill has been split into
# /context-save + /context-restore. This migration removes the old on-disk
# install so Claude Code's native /checkpoint is no longer shadowed.
#
# Ownership guard: the script only removes the install IF it owns it —
# i.e., the directory or its SKILL.md is a symlink resolving inside
# ~/.claude/skills/gstack/. A user's own /checkpoint skill (regular file,
# or symlink pointing elsewhere) is preserved.
#
# Three supported install shapes to handle:
#   1. ~/.claude/skills/checkpoint is a directory symlink into gstack.
#   2. ~/.claude/skills/checkpoint is a regular directory whose ONLY file
#      is a SKILL.md symlink into gstack (gstack's prefix-install shape).
#   3. Anything else → leave alone, print notice.
#
# Idempotent: missing paths are no-ops.
set -euo pipefail

SKILLS_DIR="${HOME}/.claude/skills"
OLD_TOPLEVEL="${SKILLS_DIR}/checkpoint"
OLD_NAMESPACED="${SKILLS_DIR}/gstack/checkpoint"
GSTACK_ROOT_REAL=""

# Resolve the canonical path of the gstack skills root. If gstack isn't
# installed here, there's nothing to migrate.
if [ -d "${SKILLS_DIR}/gstack" ]; then
  # Portable realpath: macOS BSD `readlink` lacks -f. Fall back to python3.
  if command -v realpath >/dev/null 2>&1; then
    GSTACK_ROOT_REAL=$(realpath "${SKILLS_DIR}/gstack" 2>/dev/null || true)
  fi
  if [ -z "$GSTACK_ROOT_REAL" ]; then
    GSTACK_ROOT_REAL=$(python3 -c 'import os,sys;print(os.path.realpath(sys.argv[1]))' "${SKILLS_DIR}/gstack" 2>/dev/null || true)
  fi
fi

# Helper: canonical-path a target (symlink-safe). Prints the resolved path.
resolve_real() {
  local target="$1"
  if command -v realpath >/dev/null 2>&1; then
    realpath "$target" 2>/dev/null || true
    return
  fi
  python3 -c 'import os,sys;print(os.path.realpath(sys.argv[1]))' "$target" 2>/dev/null || true
}

# Helper: does $1 (canonical path) live inside $2 (canonical path)?
path_inside() {
  local inner="$1"
  local outer="$2"
  [ -n "$inner" ] && [ -n "$outer" ] || return 1
  case "$inner" in
    "$outer"|"$outer"/*) return 0;;
    *) return 1;;
  esac
}

removed_any=0

# --- Shape 1: top-level ~/.claude/skills/checkpoint
if [ -L "$OLD_TOPLEVEL" ]; then
  # Directory symlink (or file symlink). Canonicalize and check ownership.
  target_real=$(resolve_real "$OLD_TOPLEVEL")
  if [ -n "$GSTACK_ROOT_REAL" ] && path_inside "$target_real" "$GSTACK_ROOT_REAL"; then
    rm "$OLD_TOPLEVEL"
    echo "  [v0.18.5.0] Removed stale /checkpoint symlink (was shadowing Claude Code's /rewind alias)."
    removed_any=1
  else
    echo "  [v0.18.5.0] Leaving $OLD_TOPLEVEL alone — symlink target is outside gstack."
  fi
elif [ -d "$OLD_TOPLEVEL" ]; then
  # Regular directory. Only remove if it contains exactly one file named
  # SKILL.md that's a symlink into gstack (gstack's prefix-install shape).
  entries=$(ls -A "$OLD_TOPLEVEL" 2>/dev/null)
  if [ "$entries" = "SKILL.md" ] && [ -L "$OLD_TOPLEVEL/SKILL.md" ]; then
    target_real=$(resolve_real "$OLD_TOPLEVEL/SKILL.md")
    if [ -n "$GSTACK_ROOT_REAL" ] && path_inside "$target_real" "$GSTACK_ROOT_REAL"; then
      rm -r "$OLD_TOPLEVEL"
      echo "  [v0.18.5.0] Removed stale /checkpoint install directory (gstack prefix-mode)."
      removed_any=1
    else
      echo "  [v0.18.5.0] Leaving $OLD_TOPLEVEL alone — SKILL.md symlink target is outside gstack."
    fi
  else
    echo "  [v0.18.5.0] Leaving $OLD_TOPLEVEL alone — not a gstack-owned install (has custom content)."
  fi
fi
# Missing → no-op (idempotency).

# --- Shape 2: ~/.claude/skills/gstack/checkpoint/  (gstack owns this dir unconditionally)
if [ -d "$OLD_NAMESPACED" ] || [ -L "$OLD_NAMESPACED" ]; then
  rm -rf "$OLD_NAMESPACED"
  echo "  [v0.18.5.0] Removed stale ~/.claude/skills/gstack/checkpoint/ (replaced by context-save + context-restore)."
  removed_any=1
fi

if [ "$removed_any" = "1" ]; then
  echo "  [v0.18.5.0] /checkpoint is now Claude Code's native /rewind alias. Use /context-save to save state and /context-restore to resume."
fi

exit 0
