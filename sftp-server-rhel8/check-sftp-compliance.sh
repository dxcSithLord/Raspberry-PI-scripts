#!/usr/bin/env bash
# =============================================================================
# check-sftp-compliance.sh
# -----------------------------------------------------------------------------
# READ-ONLY compliance monitor for the RHEL 8 multi-user SFTP server built by
# setup-sftp-rhel8.sh. It changes NOTHING; it only inspects the live system and
# reports whether the structure and permissions still match what the setup
# script establishes.
#
# It loads the SAME config (sftp-rhel8.conf / env vars), so the "expected"
# values are DERIVED from your configuration - there is no second copy to drift.
#
# Output : [ OK ] / [WARN] / [FAIL] per check, then a summary.
# Exit   : 0 if no FAILs (WARNs allowed); 1 if any FAIL; 2 on usage/config error.
#          -> cron/systemd-timer friendly: alert only when the exit code != 0.
#
#   Standards: NIST AC-3/AC-6 (verify least privilege & access control still
#   hold), CM-6 (configuration monitoring), AU-6 (review), DISA-STIG chroot.
#
# Usage:  sudo ./check-sftp-compliance.sh [-q] [/path/to/sftp-rhel8.conf]
#           -q, --quiet   print only WARN/FAIL lines (ideal for cron email)
# =============================================================================
set -uo pipefail               # NOT -e: every check must run to completion.

QUIET=0
CONF=""
for arg in "$@"; do
  case "$arg" in
    -q|--quiet) QUIET=1 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    -*) printf 'unknown option: %s\n' "$arg" >&2; exit 2 ;;
    *)  CONF="$arg" ;;
  esac
done

PASS=0; WARN=0; FAIL=0
ok()    { [ "$QUIET" -eq 1 ] || printf '[ OK ] %s\n' "$*"; PASS=$((PASS+1)); }
warnf() { printf '[WARN] %s\n' "$*" >&2; WARN=$((WARN+1)); }
failf() { printf '[FAIL] %s\n' "$*" >&2; FAIL=$((FAIL+1)); }
info()  { [ "$QUIET" -eq 1 ] || printf '[INFO] %s\n' "$*"; }

command -v stat    >/dev/null 2>&1 || { printf 'stat not found\n' >&2; exit 2; }
command -v findmnt >/dev/null 2>&1 || { printf 'findmnt not found\n' >&2; exit 2; }

# ------------------------------------------------- load config + env override -
CONF_VARS="SFTP_GROUP SFTP_GID SFTP_USERS SFTP_UID_BASE SFTP_DATA_BASE \
SFTP_CHROOT_BASE USE_CHROOT SFTP_PORT MOUNT_TYPE SMB_CRED_FILE ENABLE_AUDIT"
for v in $CONF_VARS; do eval "__env_${v}=\"\${${v}-__UNSET__}\""; done

: "${CONF:=/etc/sftp-server/sftp-rhel8.conf}"
if [ -f "$CONF" ]; then
  # shellcheck source=/dev/null
  . "$CONF"; info "Loaded config: $CONF"
else
  warnf "Config '$CONF' not found - checking against built-in defaults only."
fi
for v in $CONF_VARS; do
  eval "orig=\"\$__env_${v}\""
  [ "$orig" != "__UNSET__" ] && eval "${v}=\"\$orig\""
done

# Same defaults as setup-sftp-rhel8.sh so expectations line up.
: "${SFTP_GROUP:=sftpusers}"
: "${SFTP_GID:=4000}"
: "${SFTP_USERS:=sftpuser1 sftpuser2 sftpuser3}"
: "${SFTP_UID_BASE:=4001}"
: "${SFTP_DATA_BASE:=/sftp-data}"
: "${SFTP_CHROOT_BASE:=/sftp-chroot}"
: "${USE_CHROOT:=yes}"
: "${SFTP_PORT:=22}"
: "${MOUNT_TYPE:=nfs}"
: "${SMB_CRED_FILE:=/etc/sftp-server/smb.cred}"
: "${ENABLE_AUDIT:=no}"

DROPIN="/etc/ssh/sshd_config.d/50-sftp-rhel8.conf"
AK_DIR="/etc/ssh/authorized_keys"
FSTAB="/etc/fstab"

# ------------------------------------------------------------------ helpers --
# stat's %a prints octal WITHOUT a leading zero (755, 700, 600, 644, 2750).
statline() { stat -c '%U %G %a' "$1" 2>/dev/null; }
is_mount() { findmnt -rn -- "$1" >/dev/null 2>&1; }

# expect_perm PATH OWNER GROUP MODE   (MODE as stat prints it, e.g. 0755 or 755)
expect_perm() {
  local p="$1" eo="$2" eg="$3" em="${4#0}" line o g m
  if [ ! -e "$p" ]; then failf "$p is missing"; return; fi
  line="$(statline "$p")" || { failf "$p cannot be stat'd"; return; }
  read -r o g m <<<"$line"
  if [ "$o" = "$eo" ] && [ "$g" = "$eg" ] && [ "$m" = "$em" ]; then
    ok "$p  ($o:$g $m)"
  else
    failf "$p is $o:$g $m, expected $eo:$eg ${em}"
  fi
}

# not_writable_by_group_other PATH  (owner must be root:root, no g/o write bit)
key_trust_ok() {
  local p="$1" line o g m
  line="$(statline "$p")" || { failf "$p cannot be stat'd"; return; }
  read -r o g m <<<"$line"
  if [ "$o:$g" != "root:root" ]; then
    failf "$p is owned by $o:$g, expected root:root (trust anchor)"
  elif (( 8#$m & 022 )); then
    failf "$p mode $m is writable by group/other - a chrooted user could tamper with it"
  else
    ok "$p  (root:root $m, not group/other-writable)"
  fi
}

# ============================================================================
printf '===== SFTP compliance check (%s) =====\n' "$(date '+%Y-%m-%d %H:%M:%S')"
[ "$(id -u)" -eq 0 ] || warnf "Not running as root: some checks (sshd -t, mode reads) may be incomplete."

# 1. Group -------------------------------------------------------------------
if gline="$(getent group "$SFTP_GROUP")"; then
  ggid="$(printf '%s' "$gline" | cut -d: -f3)"
  [ "$ggid" = "$SFTP_GID" ] && ok "group $SFTP_GROUP (gid $ggid)" \
    || failf "group $SFTP_GROUP has gid $ggid, expected $SFTP_GID"
else
  failf "group $SFTP_GROUP does not exist"
fi

# 2. Users -------------------------------------------------------------------
idx=0
for user in $SFTP_USERS; do
  euid=$(( SFTP_UID_BASE + idx )); idx=$(( idx + 1 ))
  if ! pwline="$(getent passwd "$user")"; then
    failf "user $user does not exist"; continue
  fi
  uuid="$(printf '%s' "$pwline" | cut -d: -f3)"
  ushell="$(printf '%s' "$pwline" | cut -d: -f7)"
  ugrp="$(id -gn "$user" 2>/dev/null || echo '?')"
  [ "$uuid" = "$euid" ]            && ok "user $user uid $uuid"            || failf "user $user uid $uuid, expected $euid"
  [ "$ugrp" = "$SFTP_GROUP" ]      && ok "user $user group $ugrp"          || failf "user $user primary group $ugrp, expected $SFTP_GROUP"
  [ "$ushell" = "/sbin/nologin" ]  && ok "user $user shell nologin"        || failf "user $user shell $ushell, expected /sbin/nologin"
done

# 3. Data share --------------------------------------------------------------
expect_perm "$SFTP_DATA_BASE" root root 0755
if [ "$MOUNT_TYPE" != "none" ]; then
  is_mount "$SFTP_DATA_BASE" && ok "$SFTP_DATA_BASE is mounted ($MOUNT_TYPE)" \
    || warnf "$SFTP_DATA_BASE is NOT mounted - data unavailable until 'mount $SFTP_DATA_BASE'"
fi

# 4. Per-user data directories ----------------------------------------------
DATA_MOUNTED=0; is_mount "$SFTP_DATA_BASE" && DATA_MOUNTED=1
for user in $SFTP_USERS; do
  dir="${SFTP_DATA_BASE}/${user}"
  if [ ! -e "$dir" ]; then
    [ "$DATA_MOUNTED" -eq 1 ] && failf "$dir is missing" \
      || warnf "$dir not checked (share not mounted)"
    continue
  fi
  if [ "$MOUNT_TYPE" = "smb" ]; then
    # CIFS: ownership is governed by mount options, not per-file - existence + group only.
    g="$(stat -c '%G' "$dir" 2>/dev/null)"
    [ "$g" = "$SFTP_GROUP" ] && ok "$dir exists (group $g, ownership mount-governed)" \
      || warnf "$dir group $g (expected $SFTP_GROUP via mount gid= option)"
  else
    expect_perm "$dir" "$user" "$SFTP_GROUP" 0700
  fi
done

# 5. Chroot jails ------------------------------------------------------------
if [ "$USE_CHROOT" = "yes" ]; then
  expect_perm "$SFTP_CHROOT_BASE" root root 0755
  for user in $SFTP_USERS; do
    jail="${SFTP_CHROOT_BASE}/${user}"
    # CRITICAL: jail root must be root:root and not group/other-writable or sshd
    # refuses the session. expect_perm on 0755 covers exactly that.
    expect_perm "$jail" root root 0755
    if [ -d "${jail}/data" ]; then
      is_mount "${jail}/data" && ok "${jail}/data is bind-mounted" \
        || { [ "$DATA_MOUNTED" -eq 1 ] && failf "${jail}/data exists but is NOT a mount (bind missing)" \
             || warnf "${jail}/data not mounted (share down)"; }
    else
      failf "${jail}/data is missing"
    fi
  done
else
  info "USE_CHROOT=no: skipping chroot jail checks."
fi

# 6. authorized_keys (trust anchors) ----------------------------------------
if [ -d "$AK_DIR" ]; then
  expect_perm "$AK_DIR" root root 0755
  for user in $SFTP_USERS; do
    [ -e "${AK_DIR}/${user}" ] && key_trust_ok "${AK_DIR}/${user}" \
      || info "no authorized_keys for $user (key auth may be unused)"
  done
else
  warnf "$AK_DIR does not exist (no key-based auth configured?)"
fi

# 7. SMB credentials ---------------------------------------------------------
if [ "$MOUNT_TYPE" = "smb" ]; then
  [ -e "$SMB_CRED_FILE" ] && expect_perm "$SMB_CRED_FILE" root root 0600 \
    || failf "$SMB_CRED_FILE is missing (SMB mount cannot authenticate)"
fi

# 8. sshd drop-in ------------------------------------------------------------
if [ -e "$DROPIN" ]; then
  expect_perm "$DROPIN" root root 0600
  if command -v sshd >/dev/null 2>&1 && [ "$(id -u)" -eq 0 ]; then
    sshd -t 2>/dev/null && ok "sshd -t: configuration is valid" \
      || failf "sshd -t FAILED - sshd config is currently invalid"
  else
    warnf "sshd -t not run (need root + sshd) - skipped."
  fi
else
  failf "$DROPIN is missing (SFTP hardening not applied)"
fi

# 9. fstab persistence -------------------------------------------------------
# -F: match the marker as a literal fixed string (it is not a regex).
if grep -qF '>>> setup-sftp-rhel8.sh managed block >>>' "$FSTAB" 2>/dev/null; then
  ok "$FSTAB contains the managed mount block (persists across reboot)"
else
  [ "$MOUNT_TYPE" = "none" ] && info "$FSTAB has no managed block (MOUNT_TYPE=none)" \
    || warnf "$FSTAB has no managed block - mounts may not persist across reboot"
fi

# 10. Audit rules (only when enabled) ---------------------------------------
if [ "$ENABLE_AUDIT" = "yes" ]; then
  ARULES="/etc/audit/rules.d/50-sftp-rhel8.rules"
  [ -e "$ARULES" ] && ok "audit rule file present: $ARULES" \
    || failf "ENABLE_AUDIT=yes but $ARULES is missing"
fi

# ---------------------------------------------------------------- summary ---
printf '\n===== summary: %d OK, %d WARN, %d FAIL =====\n' "$PASS" "$WARN" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
  printf 'RESULT: NON-COMPLIANT (%d failure(s)) - re-run setup-sftp-rhel8.sh or fix manually.\n' "$FAIL" >&2
  exit 1
fi
printf 'RESULT: compliant%s\n' "$( [ "$WARN" -gt 0 ] && printf ' (with %d warning(s))' "$WARN" )"
exit 0
