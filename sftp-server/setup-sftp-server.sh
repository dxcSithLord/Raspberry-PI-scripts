#!/usr/bin/env bash
# =============================================================================
# setup-sftp-server.sh
# -----------------------------------------------------------------------------
# Provision a hardened, SFTP-only file-exchange server on RHEL 9 / RHEL 10.
#
# Two service accounts (config-driven), each in its OWN chroot jail:
#   * INTERNAL user - writes/adds/deletes files in its   inbound/  directory.
#   * EXTERNAL user - READ-ONLY access to its             outbound/ directory.
# An independent checksum service (see sftp-checksum.sh) computes a single
# SHA-256 manifest per directory and promotes files inbound -> outbound only
# after their checksum exists.
#
# -----------------------------------------------------------------------------
# SECURITY STANDARDS APPLIED (each block below is tagged [STD: ...]):
#   * DISA-STIG (RHEL 9 / OpenSSH SRG) - SSH hardening, banner, logging, chroot.
#   * NIST SP 800-53r5                 - AC-3/AC-6 (access/least privilege),
#                                        IA-5 (authenticators), AU-2/AU-12
#                                        (audit), SC-8/SC-13 (transmission &
#                                        FIPS crypto), CM-6/CM-7 (config).
#   * CIS RHEL 9 Benchmark Level 2     - service account & SSH controls.
#   * FIPS 140-3                        - approved crypto via system-wide policy.
#
# IMPORTANT - this is a GENERIC/THEORETICAL build. It assumes mandated controls
# (FIPS mode, SELinux enforcing, auditd) are ENABLED. Where a control is NOT
# enabled the script WARNS and states exactly which protection will NOT be
# enforced, then continues so it remains usable on an un-hardened dev machine.
#
# Usage:  sudo ./setup-sftp-server.sh [/path/to/sftp-server.conf]
#         Config values may be overridden by environment variables of the same
#         name. Run again any time; the script is idempotent.
# =============================================================================
set -euo pipefail
umask 077                       # anything this script creates is private by default

# ------------------------------------------------------------------ logging --
log()  { printf '[ OK ] %s\n' "$*"; }
info() { printf '[INFO] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
die()  { printf '[FAIL] %s\n' "$*" >&2; exit 1; }

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_CONF="/etc/sftp-server/sftp-server.conf"

# ------------------------------------------------- load config + env override -
# Precedence: environment variable > config file > built-in default.
# Snapshot env first so config assignments do not clobber explicit overrides.
CONF_VARS="SFTP_GROUP SFTP_GID SFTP_BASE INTERNAL_USER INTERNAL_UID INTERNAL_PUBKEY \
EXTERNAL_USER EXTERNAL_UID EXTERNAL_PUBKEY INTERNAL_PWHASH EXTERNAL_PWHASH \
ALLOW_PASSWORD_AUTH INBOUND_DIR OUTBOUND_DIR CHECKSUM_FILE SFTP_PORT \
PW_MAX_AGE PW_MIN_AGE PW_WARN_AGE"

for v in $CONF_VARS; do
  eval "__env_${v}=\"\${${v}-__UNSET__}\""
done

CONF="${1:-$DEFAULT_CONF}"
if [ -f "$CONF" ]; then
  # shellcheck source=/dev/null
  . "$CONF"
  info "Loaded config: $CONF"
else
  warn "Config file '$CONF' not found - relying on defaults and environment only."
fi

for v in $CONF_VARS; do
  eval "orig=\"\$__env_${v}\""
  [ "$orig" != "__UNSET__" ] && eval "${v}=\"\$orig\""
done

# ------------------------------------------------------------------ defaults --
: "${SFTP_GROUP:=sftpusers}"
: "${SFTP_GID:=4000}"
: "${SFTP_BASE:=/srv/sftp}"
: "${INTERNAL_USER:=int_xfer}"
: "${INTERNAL_UID:=4001}"
: "${EXTERNAL_USER:=ext_xfer}"
: "${EXTERNAL_UID:=4002}"
: "${INTERNAL_PUBKEY:=}"
: "${EXTERNAL_PUBKEY:=}"
: "${INTERNAL_PWHASH:=}"
: "${EXTERNAL_PWHASH:=}"
: "${ALLOW_PASSWORD_AUTH:=no}"
: "${INBOUND_DIR:=inbound}"
: "${OUTBOUND_DIR:=outbound}"
: "${CHECKSUM_FILE:=SHA256SUMS}"
: "${SFTP_PORT:=22}"
: "${PW_MAX_AGE:=60}"
: "${PW_MIN_AGE:=1}"
: "${PW_WARN_AGE:=7}"

# ------------------------------------------------------------ input validation --
# [STD: OWASP input validation / NIST SI-10] refuse malformed identifiers early.
valid_name() { printf '%s' "$1" | grep -Eq '^[a-z_][a-z0-9_-]{0,31}$'; }
valid_uidgid() { printf '%s' "$1" | grep -Eq '^[0-9]+$'; }

for u in "$INTERNAL_USER" "$EXTERNAL_USER" "$SFTP_GROUP"; do
  valid_name "$u" || die "invalid name '$u' (lowercase, digits, _ or -, <=32 chars)"
done
[ "$INTERNAL_USER" != "$EXTERNAL_USER" ] || die "internal and external users must differ"
for n in "$SFTP_GID" "$INTERNAL_UID" "$EXTERNAL_UID" "$SFTP_PORT" \
         "$PW_MAX_AGE" "$PW_MIN_AGE" "$PW_WARN_AGE"; do
  valid_uidgid "$n" || die "expected a number, got '$n'"
done
case "$INBOUND_DIR"  in */*|*..*|"") die "invalid INBOUND_DIR"  ;; esac
case "$OUTBOUND_DIR" in */*|*..*|"") die "invalid OUTBOUND_DIR" ;; esac
case "$CHECKSUM_FILE" in */*|*..*|"") die "invalid CHECKSUM_FILE" ;; esac

# Hashed passwords only - never accept plaintext at rest. [STD: NIST IA-5]
check_hash() {
  local val="$1" who="$2"
  [ -z "$val" ] && return 0
  case "$val" in
    '$6$'*) return 0 ;;   # SHA-512 crypt
    *) die "$who password must be a SHA-512 crypt hash ('\$6\$...'), not plaintext" ;;
  esac
}
check_hash "$INTERNAL_PWHASH" "internal"
check_hash "$EXTERNAL_PWHASH" "external"

INTERNAL_HOME="/${INBOUND_DIR}"
EXTERNAL_HOME="/${OUTBOUND_DIR}"
CHROOT_INT="${SFTP_BASE}/${INTERNAL_USER}"
CHROOT_EXT="${SFTP_BASE}/${EXTERNAL_USER}"
INBOUND_PATH="${CHROOT_INT}/${INBOUND_DIR}"
OUTBOUND_PATH="${CHROOT_EXT}/${OUTBOUND_DIR}"

# =============================================================================
# 1. PREFLIGHT - environment & mandated-control detection
# =============================================================================
[ "$(id -u)" -eq 0 ] || die "must be run as root."

command -v sshd    >/dev/null 2>&1 || die "openssh-server not installed."
command -v useradd >/dev/null 2>&1 || die "shadow-utils not installed."

# --- OS check --------------------------------------------------------------
OS_ID=""; OS_VER=""
if [ -r /etc/os-release ]; then
  # shellcheck source=/dev/null
  . /etc/os-release
  OS_ID="${ID:-}"; OS_VER="${VERSION_ID%%.*}"
fi
case "$OS_ID:$OS_VER" in
  rhel:9|rhel:10|rocky:9|rocky:10|almalinux:9|almalinux:10|centos:9|centos:10)
    log "OS supported: ${OS_ID} ${OS_VER}" ;;
  *)
    warn "Untested OS '${OS_ID} ${OS_VER}'. Designed for RHEL 9/10. Continuing." ;;
esac

# --- FIPS 140-3 ------------------------------------------------------------
# [STD: FIPS 140-3 / NIST SC-13] SSH must use FIPS-approved crypto. On RHEL this
# is delivered by the system-wide crypto policy, NOT by hardcoding ciphers.
if [ "$(cat /proc/sys/crypto/fips_enabled 2>/dev/null || echo 0)" = "1" ]; then
  log "FIPS mode is ENABLED (kernel)."
else
  warn "FIPS mode is DISABLED. SC-13/FIPS-140-3: SSH will NOT be restricted to"
  warn "  FIPS-approved algorithms. Enable with: fips-mode-setup --enable && reboot"
fi
if command -v update-crypto-policies >/dev/null 2>&1; then
  POL="$(update-crypto-policies --show 2>/dev/null || echo unknown)"
  case "$POL" in
    FIPS*) log "System crypto policy: $POL" ;;
    *) warn "Crypto policy is '$POL', not FIPS. Set with: update-crypto-policies --set FIPS" ;;
  esac
fi

# --- SELinux (audit-only per design: warn, do not manage) ------------------
# [STD: NIST AC-3 / DISA-STIG] SELinux enforcing is expected in production.
if command -v getenforce >/dev/null 2>&1; then
  SEL="$(getenforce 2>/dev/null || echo Unknown)"
  if [ "$SEL" = "Enforcing" ]; then
    log "SELinux is Enforcing."
    warn "SELinux contexts are NOT managed by this script (audit-only mode)."
    warn "  If SFTP access is denied, label the trees, e.g.:"
    warn "    semanage fcontext -a -t ssh_home_t '${SFTP_BASE}(/.*)?' && restorecon -Rv ${SFTP_BASE}"
  else
    warn "SELinux is '$SEL' (not Enforcing). AC-3 mandatory access control will"
    warn "  NOT be enforced. Enable enforcing mode in production."
  fi
fi

# --- auditd ----------------------------------------------------------------
AUDIT_OK=0
if command -v auditctl >/dev/null 2>&1 && systemctl is-active --quiet auditd 2>/dev/null; then
  AUDIT_OK=1; log "auditd is active."
else
  warn "auditd not active. AU-2/AU-12: file-transfer directory auditing will"
  warn "  NOT be recorded. Install/enable with: dnf install audit && systemctl enable --now auditd"
fi

# =============================================================================
# 2. TRANSFER GROUP           [STD: NIST AC-6 least privilege]
# =============================================================================
if getent group "$SFTP_GROUP" >/dev/null; then
  info "Group '$SFTP_GROUP' already exists."
else
  groupadd -g "$SFTP_GID" "$SFTP_GROUP"
  log "Created group '$SFTP_GROUP' (gid $SFTP_GID)."
fi

# =============================================================================
# 3. SERVICE ACCOUNTS         [STD: NIST AC-6, CIS L2 - nologin, no home login]
# =============================================================================
create_user() {
  local user="$1" uid="$2" home="$3"
  if id "$user" >/dev/null 2>&1; then
    info "User '$user' already exists."
  else
    # -M no home creation, -N no user-private group, nologin shell, locked pw.
    useradd -M -N -u "$uid" -g "$SFTP_GROUP" -d "$home" -s /sbin/nologin "$user"
    passwd -l "$user" >/dev/null    # ensure password login is locked by default
    log "Created user '$user' (uid $uid, group $SFTP_GROUP, nologin)."
  fi
}
create_user "$INTERNAL_USER" "$INTERNAL_UID" "$INTERNAL_HOME"
create_user "$EXTERNAL_USER" "$EXTERNAL_UID" "$EXTERNAL_HOME"

# =============================================================================
# 4. CHROOT JAILS + MOUNT POINTS
#    [STD: DISA-STIG chroot - the chroot dir MUST be root-owned and not
#     group/other writable, or sshd refuses the session. NIST AC-3/AC-6.]
# =============================================================================
# Separate trees so the EXTERNAL user can never see the inbound staging area.
install -d -m 0755 -o root -g root "$SFTP_BASE"
install -d -m 0755 -o root -g root "$CHROOT_INT"
install -d -m 0755 -o root -g root "$CHROOT_EXT"

# inbound: internal writes/adds/deletes. setgid keeps group = SFTP_GROUP on
# every file the internal user uploads, so the checksum service and (after
# promotion) the external reader inherit the shared group.
install -d -m 2770 -o "$INTERNAL_USER" -g "$SFTP_GROUP" "$INBOUND_PATH"

# outbound: canonical copy lives in the EXTERNAL jail. Owned by the INTERNAL
# user so that account can manage (delete) delivered files via the bind mount
# created below; 2750 gives the external user group r-x only (read/list, NEVER
# write or delete) - satisfies "file management only from the internal account".
install -d -m 2750 -o "$INTERNAL_USER" -g "$SFTP_GROUP" "$OUTBOUND_PATH"

# Bind-mount point inside the INTERNAL jail so the internal user can reach the
# same outbound directory to delete delivered files. Empty root-owned dir; the
# systemd .mount unit (section 8) mounts the canonical outbound over it.
# [STD: NIST AC-3/AC-6 - internal manages, external stays read-only]
INT_OUTBOUND_MP="${CHROOT_INT}/${OUTBOUND_DIR}"
install -d -m 0755 -o root -g root "$INT_OUTBOUND_MP"

log "Chroot trees ready:"
info "  internal jail : $CHROOT_INT  (writes -> $INBOUND_PATH, manages -> $OUTBOUND_DIR/)"
info "  external jail : $CHROOT_EXT  (reads  <- $OUTBOUND_PATH)"

# =============================================================================
# 5. AUTHENTICATION  [STD: NIST IA-5 - keys PREFERRED; passwords hashed only]
#    authorized_keys live OUTSIDE the jail, root-owned, so a chrooted user can
#    never modify their own trust anchors (DISA-STIG).
# =============================================================================
AK_DIR="/etc/ssh/authorized_keys"
install -d -m 0755 -o root -g root "$AK_DIR"

install_key() {
  local user="$1" key="$2"
  [ -z "$key" ] && { info "No public key supplied for '$user' (key auth skipped)."; return; }
  printf '%s\n' "$key" > "${AK_DIR}/${user}"
  chown root:root "${AK_DIR}/${user}"
  chmod 0644 "${AK_DIR}/${user}"
  log "Installed authorized_keys for '$user'."
}
install_key "$INTERNAL_USER" "$INTERNAL_PUBKEY"
install_key "$EXTERNAL_USER" "$EXTERNAL_PUBKEY"

set_password() {
  local user="$1" hash="$2"
  [ -z "$hash" ] && return 0
  [ "$ALLOW_PASSWORD_AUTH" = "yes" ] || {
    warn "Password hash given for '$user' but ALLOW_PASSWORD_AUTH != yes; ignoring."
    return 0; }
  printf '%s:%s\n' "$user" "$hash" | chpasswd -e
  # [STD: CIS/STIG] enforce rotation policy on the account.
  chage --maxdays "$PW_MAX_AGE" --mindays "$PW_MIN_AGE" --warndays "$PW_WARN_AGE" "$user"
  log "Set hashed password + rotation policy for '$user'."
}
set_password "$INTERNAL_USER" "$INTERNAL_PWHASH"
set_password "$EXTERNAL_USER" "$EXTERNAL_PWHASH"

# =============================================================================
# 6. SSH / SFTP HARDENING     [STD: DISA-STIG OpenSSH SRG, NIST SC-8, CIS L2]
#    Written as a drop-in so the stock sshd_config is left intact (CM-6).
# =============================================================================
BANNER="/etc/ssh/sftp-banner.txt"
if [ ! -f "$BANNER" ]; then
  cat > "$BANNER" <<'EOF'
********************************************************************************
*                              AUTHORISED USE ONLY                             *
* This system is for authorised file-transfer use only. Activity is monitored  *
* and logged. Unauthorised access is prohibited and may be prosecuted.         *
********************************************************************************
EOF
  chmod 0644 "$BANNER"
fi

# Per-user password auth: on only when explicitly allowed AND a hash exists.
int_pw="no"; ext_pw="no"
[ "$ALLOW_PASSWORD_AUTH" = "yes" ] && [ -n "$INTERNAL_PWHASH" ] && int_pw="yes"
[ "$ALLOW_PASSWORD_AUTH" = "yes" ] && [ -n "$EXTERNAL_PWHASH" ] && ext_pw="yes"

DROPIN="/etc/ssh/sshd_config.d/50-sftp-hardening.conf"
install -d -m 0755 /etc/ssh/sshd_config.d
cat > "$DROPIN" <<EOF
# Managed by setup-sftp-server.sh - do not edit by hand.
# [STD: DISA-STIG OpenSSH SRG / NIST SC-8, IA-5, AU-3 / CIS RHEL 9 L2]

Port ${SFTP_PORT}

# --- Global authentication policy -----------------------------------------
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
MaxAuthTries 4
LoginGraceTime 30
AuthorizedKeysFile ${AK_DIR}/%u .ssh/authorized_keys

# --- Session hygiene -------------------------------------------------------
ClientAliveInterval 300
ClientAliveCountMax 2
Banner ${BANNER}

# --- Audit-grade logging ---------------------------------------------------
# Each user below is ForceCommand'd to internal-sftp with '-l INFO -f AUTHPRIV',
# which logs every open/close/rename/remove. The global 'Subsystem sftp' line
# is intentionally NOT redefined here: the stock sshd_config already defines it
# and a second definition makes 'sshd -t' fail ("Subsystem already defined").
LogLevel VERBOSE

# --- INTERNAL user: writer, chrooted, SFTP-only ---------------------------
Match User ${INTERNAL_USER}
    ChrootDirectory ${CHROOT_INT}
    ForceCommand internal-sftp -u 0027 -f AUTHPRIV -l INFO
    PasswordAuthentication ${int_pw}
    AllowTcpForwarding no
    AllowStreamLocalForwarding no
    AllowAgentForwarding no
    X11Forwarding no
    PermitTunnel no
    PermitTTY no

# --- EXTERNAL user: reader, chrooted, SFTP-only ---------------------------
Match User ${EXTERNAL_USER}
    ChrootDirectory ${CHROOT_EXT}
    ForceCommand internal-sftp -u 0027 -f AUTHPRIV -l INFO
    PasswordAuthentication ${ext_pw}
    AllowTcpForwarding no
    AllowStreamLocalForwarding no
    AllowAgentForwarding no
    X11Forwarding no
    PermitTunnel no
    PermitTTY no
EOF
chmod 0600 "$DROPIN"
log "Wrote sshd drop-in: $DROPIN"

# Validate BEFORE reloading - never leave sshd unable to start. [STD: CM-6]
if sshd -t; then
  systemctl reload sshd 2>/dev/null || systemctl restart sshd
  log "sshd configuration validated and reloaded."
else
  die "sshd -t failed. Drop-in left in place for inspection; sshd NOT reloaded."
fi

# =============================================================================
# 7. AUDIT RULES              [STD: NIST AU-2/AU-12, DISA-STIG]
# =============================================================================
if [ "$AUDIT_OK" -eq 1 ]; then
  ARULES="/etc/audit/rules.d/50-sftp.rules"
  cat > "$ARULES" <<EOF
## Managed by setup-sftp-server.sh - SFTP transfer directory auditing.
## [STD: NIST AU-2/AU-12 - record additions/removals/attribute changes]
-w ${INBOUND_PATH} -p wa -k sftp_inbound
-w ${OUTBOUND_PATH} -p wa -k sftp_outbound
EOF
  chmod 0640 "$ARULES"
  augenrules --load >/dev/null 2>&1 || auditctl -R "$ARULES" >/dev/null 2>&1 || \
    warn "Could not load audit rules now; they will apply on next auditd restart."
  log "Installed audit rules: $ARULES"
fi

# =============================================================================
# 8. CHECKSUM SERVICE (independent) - manifest + inbound->outbound promotion
#    [STD: FIPS 140-3 SHA-256, NIST SI-7 integrity]
# =============================================================================
CHK_INSTALL="/usr/local/sbin/sftp-checksum.sh"
install -m 0750 -o root -g root "${SCRIPT_DIR}/sftp-checksum.sh" "$CHK_INSTALL"
log "Installed checksum script: $CHK_INSTALL"

render_unit() {
  local src="$1" dst="$2"
  sed -e "s#@SCRIPT@#${CHK_INSTALL}#g" \
      -e "s#@INBOUND@#${INBOUND_PATH}#g" \
      -e "s#@OUTBOUND@#${OUTBOUND_PATH}#g" \
      -e "s#@MANIFEST@#${CHECKSUM_FILE}#g" \
      "$src" > "$dst"
  chmod 0644 "$dst"
}
render_unit "${SCRIPT_DIR}/systemd/sftp-checksum.service.in" \
            "/etc/systemd/system/sftp-checksum.service"
render_unit "${SCRIPT_DIR}/systemd/sftp-checksum.path.in" \
            "/etc/systemd/system/sftp-checksum.path"
systemctl daemon-reload
systemctl enable --now sftp-checksum.path
log "Enabled real-time checksum watcher (sftp-checksum.path)."

# --- Bind-mount outbound into the internal jail ------------------------------
# Lets the internal user reach the canonical outbound dir to DELETE delivered
# files, while the external user keeps its own read-only view. Same inode both
# sides; external access stays limited by the 2750 group r-x permission.
# The .mount unit filename MUST equal the escaped mount-point path.
MOUNT_UNIT="$(systemd-escape -p --suffix=mount "$INT_OUTBOUND_MP")"
cat > "/etc/systemd/system/${MOUNT_UNIT}" <<EOF
# Managed by setup-sftp-server.sh - bind outbound into the internal jail.
# [STD: NIST AC-3/AC-6 - internal manages delivered files; external read-only]
[Unit]
Description=Bind SFTP outbound into internal jail (${INTERNAL_USER})
After=local-fs.target
RequiresMountsFor=${OUTBOUND_PATH}

[Mount]
What=${OUTBOUND_PATH}
Where=${INT_OUTBOUND_MP}
Type=none
Options=bind

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "/etc/systemd/system/${MOUNT_UNIT}"
systemctl daemon-reload
systemctl enable --now "$MOUNT_UNIT"
log "Bind-mounted outbound into internal jail ($INT_OUTBOUND_MP)."

# =============================================================================
# 9. SUMMARY
# =============================================================================
cat <<EOF

============================ SFTP SERVER READY ============================
  Group            : ${SFTP_GROUP} (gid ${SFTP_GID})
  Internal (write) : ${INTERNAL_USER}  ->  ${INBOUND_DIR}/ (write) + ${OUTBOUND_DIR}/ (manage/delete)
  External (read)  : ${EXTERNAL_USER}  ->  ${OUTBOUND_DIR}/ (read-only)
  Chroot base      : ${SFTP_BASE}
  Manifest         : ${OUTBOUND_PATH}/${CHECKSUM_FILE}
  SSH drop-in      : ${DROPIN}
  Listen port      : ${SFTP_PORT}
  Password auth    : ALLOW_PASSWORD_AUTH=${ALLOW_PASSWORD_AUTH} (keys preferred)

  Flow: internal uploads to inbound/  ->  checksum service hashes + moves the
        file to outbound/  ->  external reads and can verify with:
          sha256sum -c ${CHECKSUM_FILE}
  The internal user also sees outbound/ (bind mount) and may delete delivered
  files there; the manifest refreshes on the next upload, or run:
          ${CHK_INSTALL} ${INBOUND_PATH} ${OUTBOUND_PATH} ${CHECKSUM_FILE}

  Review any [WARN] lines above: they mark controls (FIPS, SELinux, auditd)
  that are NOT enforced unless enabled on this host.
==========================================================================
EOF
