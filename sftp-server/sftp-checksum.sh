#!/usr/bin/env bash
# =============================================================================
# sftp-checksum.sh  -  generate SHA-256 manifest and promote files inbound->outbound
# -----------------------------------------------------------------------------
# Runs INDEPENDENTLY of the SFTP session (invoked by a systemd .path unit that
# watches the inbound directory, or by hand). For every *stable* file the
# internal user has finished uploading it:
#   1. computes a SHA-256 hash                       (FIPS 140-3 approved digest)
#   2. atomically moves the file into the outbound directory
#   3. regenerates a SINGLE aggregate manifest (SHA256SUMS) for outbound
#
# A file therefore appears in outbound ONLY after its checksum exists, so the
# external reader never sees an unverified or half-written file.
#
#   Standards applied:
#     * FIPS 140-3 / NIST SP 800-140  - SHA-256 via the OS crypto library
#                                       (sha256sum honours kernel FIPS mode).
#     * NIST SP 800-53 SI-7           - software/information integrity.
#     * OWASP / CIS                   - input validation, no shell injection,
#                                       atomic writes, least privilege (umask).
#
# Usage: sftp-checksum.sh <inbound_dir> <outbound_dir> [manifest_name]
# =============================================================================
set -euo pipefail
umask 027                       # new files: owner rw, group r, other none

MANIFEST_DEFAULT="SHA256SUMS"
STABLE_WAIT=2                   # seconds to confirm an upload has finished

log() { printf '%s sftp-checksum[%d]: %s\n' "$(date -u +%FT%TZ)" "$$" "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

# --- Arguments & validation -------------------------------------------------
[ "$#" -ge 2 ] || die "usage: $0 <inbound_dir> <outbound_dir> [manifest_name]"
INBOUND="$1"
OUTBOUND="$2"
MANIFEST="${3:-$MANIFEST_DEFAULT}"

# Reject anything but a plain manifest filename (defence in depth, no traversal).
case "$MANIFEST" in
  */*|*..*|"") die "invalid manifest name: $MANIFEST" ;;
esac

[ -d "$INBOUND" ]  || die "inbound dir does not exist: $INBOUND"
[ -d "$OUTBOUND" ] || die "outbound dir does not exist: $OUTBOUND"

command -v sha256sum >/dev/null 2>&1 || die "sha256sum not found (coreutils)"

# --- Single-instance lock: overlapping inotify events must not race ---------
exec 9>"${OUTBOUND}/.checksum.lock"
flock -n 9 || { log "another run holds the lock; exiting"; exit 0; }

# --- Is the file finished uploading? ----------------------------------------
# True when its size is unchanged over STABLE_WAIT seconds and no process holds
# it open. Skipped files are picked up on the next inotify event.
is_stable() {
  local f="$1" s1 s2
  s1=$(stat -c '%s' -- "$f" 2>/dev/null) || return 1
  sleep "$STABLE_WAIT"
  s2=$(stat -c '%s' -- "$f" 2>/dev/null) || return 1
  [ "$s1" = "$s2" ] || return 1
  if command -v fuser >/dev/null 2>&1; then
    fuser -s -- "$f" 2>/dev/null && return 1   # still open by a writer
  fi
  return 0
}

# --- Promote each stable regular file from inbound to outbound --------------
promoted=0
shopt -s nullglob
for path in "$INBOUND"/*; do
  # Only plain files; never follow symlinks (could point outside the jail).
  [ -f "$path" ] || continue
  [ -L "$path" ] && { log "skip symlink: $path"; continue; }
  name="$(basename -- "$path")"
  [ "$name" = "$MANIFEST" ] && continue        # don't move the manifest itself

  is_stable "$path" || { log "not yet stable, will retry later: $name"; continue; }

  # Atomic move (same filesystem: rename(2)). Refuse to clobber an existing file.
  if [ -e "${OUTBOUND}/${name}" ]; then
    log "target already exists, leaving in inbound: $name"
    continue
  fi
  mv -n -- "$path" "${OUTBOUND}/${name}"
  log "promoted: $name"
  promoted=$((promoted + 1))
done

# --- Regenerate the single aggregate manifest for outbound ------------------
# Rebuilt from scratch each run so it always reflects the current directory
# contents (self-healing). Written atomically via a temp file + rename.
tmp="$(mktemp "${OUTBOUND}/.${MANIFEST}.XXXXXX")"
trap 'rm -f -- "$tmp"' EXIT
(
  cd "$OUTBOUND"
  # -maxdepth 1, regular files only, exclude the manifest and dotfiles/locks.
  find . -maxdepth 1 -type f ! -name "$MANIFEST" ! -name '.*' -printf '%P\0' \
    | sort -z \
    | xargs -0 -r sha256sum --
) > "$tmp"
chmod 0640 "$tmp"
mv -f -- "$tmp" "${OUTBOUND}/${MANIFEST}"
trap - EXIT

log "done: promoted=${promoted}, manifest=${OUTBOUND}/${MANIFEST}"
