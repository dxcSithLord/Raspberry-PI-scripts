#!/usr/bin/env bash
# =============================================================================
# setup-sftp-rhel8.sh
# -----------------------------------------------------------------------------
# Provision a hardened, SFTP-only server on RHEL 8 for a set of INTERNAL users.
#
#   * N dedicated SFTP users (config-driven list) - each can UPLOAD and
#     DOWNLOAD files in its own directory.
#   * User data lives on a single NFS or SMB share mounted at /sftp-data,
#     with a per-user subdirectory. NFSv4 is preferred.
#   * Users have NO shell (/sbin/nologin) and are forced to internal-sftp.
#   * Chroot jail is OPTIONAL (USE_CHROOT). When on, /sftp-chroot/<user> is a
#     root-owned jail whose 'data/' is a BIND MOUNT of /sftp-data/<user>.
#   * External transfer is handled by the mount, so there is NO checksum step.
#   * Audit of transfers is OPTIONAL (ENABLE_AUDIT).
#
# -----------------------------------------------------------------------------
# SECURITY STANDARDS APPLIED (each block below is tagged [STD: ...]):
#   * DISA-STIG (RHEL 8 / OpenSSH SRG) - SSH hardening, banner, logging, chroot.
#   * NIST SP 800-53r5                 - AC-3/AC-6 (access/least privilege),
#                                        IA-5 (authenticators), AU-2/AU-12
#                                        (audit), SC-8/SC-13 (transmission &
#                                        FIPS crypto), CM-6/CM-7 (config).
#   * CIS RHEL 8 Benchmark Level 2     - service account, mount & SSH controls.
#   * FIPS 140-3                        - approved crypto via system-wide policy.
#
# IMPORTANT - this is a GENERIC build. It assumes mandated controls (FIPS mode,
# SELinux enforcing, auditd) are ENABLED. Where a control is NOT enabled the
# script WARNS and states exactly which protection will NOT be enforced, then
# continues so it stays usable on an un-hardened dev machine.
#
# Usage:  sudo ./setup-sftp-rhel8.sh [/path/to/sftp-rhel8.conf]
#         Config values may be overridden by environment variables of the same
#         name. Re-run any time; the script is idempotent.
# =============================================================================
set -euo pipefail
umask 077                       # anything this script creates is private by default

# ------------------------------------------------------------------ logging --
log()  { printf '[ OK ] %s\n' "$*"; }
info() { printf '[INFO] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
die()  { printf '[FAIL] %s\n' "$*" >&2; exit 1; }

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_CONF="/etc/sftp-server/sftp-rhel8.conf"
FSTAB="/etc/fstab"
FSTAB_BEGIN="# >>> setup-sftp-rhel8.sh managed block >>>"
FSTAB_END="# <<< setup-sftp-rhel8.sh managed block <<<"

# ------------------------------------------------- load config + env override -
# Precedence: environment variable > config file > built-in default.
# Snapshot env first so config assignments do not clobber explicit overrides.
# (Per-user PUBKEY_<user>/PWHASH_<user> are resolved later by indirect lookup.)
CONF_VARS="SFTP_GROUP SFTP_GID SFTP_USERS SFTP_UID_BASE SFTP_DATA_BASE \
SFTP_CHROOT_BASE USE_CHROOT SFTP_PORT ALLOW_PASSWORD_AUTH ENABLE_AUDIT \
MOUNT_TYPE MOUNT_SOURCE NFS_OPTIONS SMB_OPTIONS SMB_CRED_FILE \
SMB_USERNAME SMB_PASSWORD SMB_DOMAIN PW_MAX_AGE PW_MIN_AGE PW_WARN_AGE"

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
: "${SFTP_USERS:=sftpuser1 sftpuser2 sftpuser3}"
: "${SFTP_UID_BASE:=4001}"
: "${SFTP_DATA_BASE:=/sftp-data}"
: "${SFTP_CHROOT_BASE:=/sftp-chroot}"
: "${USE_CHROOT:=yes}"
: "${SFTP_PORT:=22}"
: "${ALLOW_PASSWORD_AUTH:=no}"
: "${ENABLE_AUDIT:=no}"
: "${PW_MAX_AGE:=60}"
: "${PW_MIN_AGE:=1}"
: "${PW_WARN_AGE:=7}"

# --- Mount defaults (reference SFTP_GID, so they come AFTER it) --------------
: "${MOUNT_TYPE:=nfs}"                       # nfs | smb | none
: "${MOUNT_SOURCE:=}"                        # nfs: host:/export   smb: //host/share
# NFSv4 preferred; noexec/nosuid/nodev harden the data area (CIS). [STD: CIS]
: "${NFS_OPTIONS:=rw,hard,vers=4.2,_netdev,nosuid,nodev,noexec}"
: "${SMB_CRED_FILE:=/etc/sftp-server/smb.cred}"
: "${SMB_USERNAME:=}"
: "${SMB_PASSWORD:=}"
: "${SMB_DOMAIN:=}"
# CIFS maps the whole mount to one identity: files present as group SFTP_GID so
# every chrooted sftp user can read/write its own subtree. Isolation between
# users on SMB relies on the chroot + separate subdirs, NOT on Unix ownership.
: "${SMB_OPTIONS:=vers=3.1.1,uid=0,forceuid,gid=${SFTP_GID},forcegid,file_mode=0660,dir_mode=0770,_netdev,nosuid,nodev,noexec}"

# ------------------------------------------------------------ input validation --
# [STD: OWASP input validation / NIST SI-10] refuse malformed identifiers early.
# POSIX Extended Regular Expressions (ERE) via 'grep -E'.
#   Ref: IEEE Std 1003.1-2017 (POSIX.1), Base Definitions §9.4 (EREs).
#
# valid_name: 1-32 chars; first is a lowercase letter or '_', rest add digits
# and '-'. Mirrors the shadow-utils useradd NAME_REGEX / login.defs convention
# (distro default `^[a-z_][a-z0-9_-]*$`), lower-cased for hardening, and caps at
# 32 = the useradd name limit (sysconf LOGIN_NAME_MAX). The '-' is last in the
# bracket so it is a literal, not a range.
#   Ref: useradd(8) & login.defs(5) (shadow-utils, chkname.c is_valid_user_name);
#        POSIX.1-2017 §3.437 "User Name" (Portable Filename Character Set).
valid_name()   { printf '%s' "$1" | grep -Eq '^[a-z_][a-z0-9_-]{0,31}$'; }
# valid_number: one or more ASCII digits (unsigned integer). Range is checked
# separately where it matters (see SFTP_PORT below).
valid_number() { printf '%s' "$1" | grep -Eq '^[0-9]+$'; }

valid_name "$SFTP_GROUP" || die "invalid group '$SFTP_GROUP'"
[ -n "${SFTP_USERS// }" ] || die "SFTP_USERS is empty - list at least one user."
for u in $SFTP_USERS; do
  valid_name "$u" || die "invalid user name '$u' (lowercase, digits, _ or -, <=32 chars)"
done
for n in "$SFTP_GID" "$SFTP_UID_BASE" "$SFTP_PORT" \
         "$PW_MAX_AGE" "$PW_MIN_AGE" "$PW_WARN_AGE"; do
  valid_number "$n" || die "expected a number, got '$n'"
done
# A digit string is not enough for a TCP port - bound it to 1..65535.
[ "$SFTP_PORT" -ge 1 ] && [ "$SFTP_PORT" -le 65535 ] || die "SFTP_PORT must be 1-65535, got '$SFTP_PORT'"
case "$USE_CHROOT"          in yes|no) ;; *) die "USE_CHROOT must be yes or no" ;; esac
case "$ENABLE_AUDIT"        in yes|no) ;; *) die "ENABLE_AUDIT must be yes or no" ;; esac
case "$ALLOW_PASSWORD_AUTH" in yes|no) ;; *) die "ALLOW_PASSWORD_AUTH must be yes or no" ;; esac
case "$MOUNT_TYPE"          in nfs|smb|none) ;; *) die "MOUNT_TYPE must be nfs, smb or none" ;; esac
case "$SFTP_DATA_BASE"   in /*) ;; *) die "SFTP_DATA_BASE must be an absolute path" ;; esac
case "$SFTP_CHROOT_BASE" in /*) ;; *) die "SFTP_CHROOT_BASE must be an absolute path" ;; esac
[ "$SFTP_DATA_BASE" != "/" ] && [ "$SFTP_CHROOT_BASE" != "/" ] || die "base paths must not be '/'"
[ "$SFTP_DATA_BASE" != "$SFTP_CHROOT_BASE" ] || die "data and chroot bases must differ"

# Reject a source with whitespace/newlines (would corrupt the fstab line).
if [ "$MOUNT_TYPE" != "none" ]; then
  [ -n "$MOUNT_SOURCE" ] || die "MOUNT_TYPE=$MOUNT_TYPE requires MOUNT_SOURCE."
  case "$MOUNT_SOURCE" in *[[:space:]]*) die "MOUNT_SOURCE must not contain whitespace" ;; esac
fi
[ "$MOUNT_TYPE" != "nfs" ] || case "$MOUNT_SOURCE" in *:/*) ;; *) die "NFS MOUNT_SOURCE must look like host:/export" ;; esac
[ "$MOUNT_TYPE" != "smb" ] || case "$MOUNT_SOURCE" in //*) ;; *) die "SMB MOUNT_SOURCE must look like //host/share" ;; esac

# Indirect per-user lookup: PUBKEY_<user> / PWHASH_<user> (user sanitised to a
# valid shell identifier: any char outside [A-Za-z0-9_] becomes '_'). The
# pattern is a glob bracket expression in bash pattern substitution, not an ERE.
#   Ref: Bash Reference Manual §3.5.3 Shell Parameter Expansion (${var//pat/rep})
#        and §3.5.8.1 Pattern Matching; shell name charset per POSIX.1-2017 §3.235.
user_var() {
  local prefix="$1" user="$2" san name
  san="${user//[^A-Za-z0-9_]/_}"
  name="${prefix}_${san}"
  printf '%s' "${!name-}"
}

# Hashed passwords only - never accept plaintext at rest. [STD: NIST IA-5]
# The '$6$' prefix is the crypt(5) identifier for a SHA-512 password hash; the
# check is a glob (case pattern), not a regex.
#   Ref: crypt(5) man page (Linux man-pages) - '$6$' = SHA-512; also
#        `openssl passwd -6` / `mkpasswd -m sha-512` which emit this format.
check_hash() {
  local val="$1" who="$2"
  [ -z "$val" ] && return 0
  case "$val" in
    '$6$'*) return 0 ;;   # SHA-512 crypt
    *) die "$who password must be a SHA-512 crypt hash ('\$6\$...'), not plaintext" ;;
  esac
}
for u in $SFTP_USERS; do
  check_hash "$(user_var PWHASH "$u")" "$u"
done

# =============================================================================
# 1. PREFLIGHT - environment & mandated-control detection
# =============================================================================
[ "$(id -u)" -eq 0 ] || die "must be run as root."

command -v sshd    >/dev/null 2>&1 || die "openssh-server not installed."
command -v useradd >/dev/null 2>&1 || die "shadow-utils not installed."
command -v findmnt >/dev/null 2>&1 || die "util-linux (findmnt) not installed."

# --- OS check --------------------------------------------------------------
OS_ID=""; OS_VER=""
if [ -r /etc/os-release ]; then
  # shellcheck source=/dev/null
  . /etc/os-release
  OS_ID="${ID:-}"; OS_VER="${VERSION_ID%%.*}"
fi
case "$OS_ID:$OS_VER" in
  rhel:8|rocky:8|almalinux:8|centos:8)
    log "OS supported: ${OS_ID} ${OS_VER}" ;;
  *)
    warn "Untested OS '${OS_ID} ${OS_VER}'. Designed for RHEL 8. Continuing." ;;
esac

# --- Mount client packages -------------------------------------------------
case "$MOUNT_TYPE" in
  nfs) command -v mount.nfs4 >/dev/null 2>&1 || command -v mount.nfs >/dev/null 2>&1 \
         || warn "nfs-utils not found. Install with: dnf install nfs-utils" ;;
  smb) command -v mount.cifs >/dev/null 2>&1 \
         || warn "cifs-utils not found. Install with: dnf install cifs-utils" ;;
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
    warn "SELinux contexts are NOT managed by this script (audit-only mode). If SFTP"
    warn "  access to the share is denied, you likely need the network-FS boolean and"
    warn "  a label on the trees, e.g.:"
    [ "$MOUNT_TYPE" = "smb" ] \
      && warn "    setsebool -P use_samba_home_dirs on" \
      || warn "    setsebool -P use_nfs_home_dirs on"
    warn "    semanage fcontext -a -t ssh_home_t '${SFTP_CHROOT_BASE}(/.*)?' && restorecon -Rv ${SFTP_CHROOT_BASE}"
  else
    warn "SELinux is '$SEL' (not Enforcing). AC-3 mandatory access control will"
    warn "  NOT be enforced. Enable enforcing mode in production."
  fi
fi

# --- auditd (only relevant when ENABLE_AUDIT=yes) --------------------------
AUDIT_OK=0
if command -v auditctl >/dev/null 2>&1 && systemctl is-active --quiet auditd 2>/dev/null; then
  AUDIT_OK=1
  [ "$ENABLE_AUDIT" = "yes" ] && log "auditd is active."
elif [ "$ENABLE_AUDIT" = "yes" ]; then
  warn "ENABLE_AUDIT=yes but auditd is not active. AU-2/AU-12: transfer-directory"
  warn "  auditing will NOT be recorded. Enable with: dnf install audit && systemctl enable --now auditd"
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
#    UIDs are assigned deterministically as SFTP_UID_BASE + index for
#    reproducible deployments. Home is /data (inside the jail) when chrooted,
#    else the user's data dir.
# =============================================================================
idx=0
for user in $SFTP_USERS; do
  uid=$(( SFTP_UID_BASE + idx )); idx=$(( idx + 1 ))
  if [ "$USE_CHROOT" = "yes" ]; then home="/data"; else home="${SFTP_DATA_BASE}/${user}"; fi
  if id "$user" >/dev/null 2>&1; then
    info "User '$user' already exists."
    continue
  fi
  # Guard against reusing a UID that belongs to a different account.
  if existing="$(getent passwd "$uid" | cut -d: -f1)" && [ -n "$existing" ]; then
    die "UID $uid already used by '$existing'. Adjust SFTP_UID_BASE or SFTP_USERS."
  fi
  # -M no home creation, -N no user-private group, nologin shell, locked pw.
  useradd -M -N -u "$uid" -g "$SFTP_GROUP" -d "$home" -s /sbin/nologin "$user"
  passwd -l "$user" >/dev/null    # ensure password login is locked by default
  log "Created user '$user' (uid $uid, group $SFTP_GROUP, nologin, home $home)."
done

# =============================================================================
# 4. STORAGE MOUNT (single share at SFTP_DATA_BASE)  [STD: CIS mount options]
#    fstab is edited between managed markers so re-runs replace the block
#    cleanly. A timestamped backup is written before every change (CM-6).
# =============================================================================
install -d -m 0755 -o root -g root "$SFTP_DATA_BASE"   # mount point (pre-mount)

# --- SMB credentials: create the shared-account mapping if it is missing ----
# [STD: NIST IA-5] one shared SMB service account; local sftp users reach the
# share through this credential + the uid/gid mount options. File is root-only.
if [ "$MOUNT_TYPE" = "smb" ]; then
  if [ -f "$SMB_CRED_FILE" ]; then
    chown root:root "$SMB_CRED_FILE"; chmod 0600 "$SMB_CRED_FILE"
    info "SMB credentials file exists: $SMB_CRED_FILE (re-secured root:root 0600)."
  else
    install -d -m 0700 -o root -g root "$(dirname "$SMB_CRED_FILE")"
    ( umask 077
      {
        printf 'username=%s\n' "${SMB_USERNAME:-CHANGEME}"
        printf 'password=%s\n' "${SMB_PASSWORD:-CHANGEME}"
        [ -n "$SMB_DOMAIN" ] && printf 'domain=%s\n' "$SMB_DOMAIN"
      } > "$SMB_CRED_FILE" )
    chown root:root "$SMB_CRED_FILE"; chmod 0600 "$SMB_CRED_FILE"
    if [ -z "$SMB_USERNAME" ] || [ -z "$SMB_PASSWORD" ]; then
      warn "Created PLACEHOLDER $SMB_CRED_FILE - edit it with the real SMB service"
      warn "  account (username=/password=/domain=), keep it 0600, then re-run."
    else
      log "Created SMB credentials file $SMB_CRED_FILE (root:root 0600)."
    fi
  fi
fi

# --- Assemble the managed fstab block ---------------------------------------
FSTAB_BLOCK=""
add_line() { FSTAB_BLOCK="${FSTAB_BLOCK}${1}"$'\n'; }

case "$MOUNT_TYPE" in
  nfs) add_line "${MOUNT_SOURCE} ${SFTP_DATA_BASE} nfs ${NFS_OPTIONS} 0 0" ;;
  smb) add_line "${MOUNT_SOURCE} ${SFTP_DATA_BASE} cifs ${SMB_OPTIONS},credentials=${SMB_CRED_FILE} 0 0" ;;
  none) info "MOUNT_TYPE=none: assuming an admin mounts ${SFTP_DATA_BASE} separately." ;;
esac

# Per-user bind mounts into the chroot jail (only when chroot is enabled).
# A symlink to ${SFTP_DATA_BASE}/<user> would point OUTSIDE the jail and break,
# so the writable 'data' dir is a bind mount instead. [STD: DISA-STIG chroot]
if [ "$USE_CHROOT" = "yes" ]; then
  for user in $SFTP_USERS; do
    add_line "${SFTP_DATA_BASE}/${user} ${SFTP_CHROOT_BASE}/${user}/data none bind,nosuid,nodev,noexec,x-systemd.requires=${SFTP_DATA_BASE} 0 0"
  done
fi

# --- Write the block (idempotent) -------------------------------------------
if [ -n "$FSTAB_BLOCK" ]; then
  tmp="$(mktemp)"
  # Drop any previous managed block; keep everything else verbatim, and trim
  # trailing blank lines so the file stays byte-stable across re-runs.
  # awk ERE '/[^[:space:]]/' matches a line with any non-whitespace char, used
  # to remember the last non-blank line so trailing blanks are dropped.
  #   Ref: POSIX.1-2017 awk (regex) and Base Definitions §9.3.5 ([:space:] class).
  awk -v b="$FSTAB_BEGIN" -v e="$FSTAB_END" '
    $0==b {skip=1; next}
    $0==e {skip=0; next}
    skip==0 { lines[++n]=$0; if ($0 ~ /[^[:space:]]/) last=n }
    END { for (i=1; i<=last; i++) print lines[i] }
  ' "$FSTAB" > "$tmp"
  { printf '\n%s\n' "$FSTAB_BEGIN"
    printf '%s' "$FSTAB_BLOCK"
    printf '%s\n' "$FSTAB_END"; } >> "$tmp"
  install -m 0644 -o root -g root "$FSTAB" "${FSTAB}.sftp-rhel8.$(date +%Y%m%d%H%M%S).bak"
  install -m 0644 -o root -g root "$tmp" "$FSTAB"
  rm -f "$tmp"
  systemctl daemon-reload
  log "Updated ${FSTAB} (managed block) and reloaded systemd."
fi

# --- Activate the network mount ---------------------------------------------
if [ "$MOUNT_TYPE" != "none" ]; then
  if findmnt -rn -- "$SFTP_DATA_BASE" >/dev/null 2>&1; then
    info "${SFTP_DATA_BASE} is already mounted."
  elif mount "$SFTP_DATA_BASE" 2>/dev/null; then
    log "Mounted ${SFTP_DATA_BASE} (${MOUNT_TYPE})."
  else
    warn "Could not mount ${SFTP_DATA_BASE} now (server unreachable or credentials"
    warn "  incomplete). fstab is in place; it will mount on boot or 'mount ${SFTP_DATA_BASE}'."
  fi
fi

# =============================================================================
# 5. PER-USER DATA DIRECTORIES (only when the share is actually mounted, so we
#    never write into the empty mount point on the local root filesystem).
# =============================================================================
MOUNTED=0
findmnt -rn -- "$SFTP_DATA_BASE" >/dev/null 2>&1 && MOUNTED=1
if [ "$MOUNT_TYPE" = "none" ] && [ "$MOUNTED" -eq 0 ]; then
  warn "${SFTP_DATA_BASE} is not a mount point. Mount it, then re-run to create the"
  warn "  per-user directories on the share."
fi

if [ "$MOUNTED" -eq 1 ]; then
  for user in $SFTP_USERS; do
    dir="${SFTP_DATA_BASE}/${user}"
    if [ "$MOUNT_TYPE" = "smb" ]; then
      # CIFS does not honour chown/chmod: ownership/mode come from mount options.
      mkdir -p "$dir" 2>/dev/null \
        && info "SMB: $dir ready (ownership via mount uid/gid/dir_mode)." \
        || warn "Could not create $dir on the SMB share."
    else
      # NFSv4 / local: real per-user ownership, owner-only (least privilege).
      install -d -m 0700 -o "$user" -g "$SFTP_GROUP" "$dir"
      info "$dir ready ($user:$SFTP_GROUP 0700)."
    fi
  done
else
  warn "Skipping per-user directory creation until ${SFTP_DATA_BASE} is mounted."
fi

# =============================================================================
# 6. CHROOT JAILS + BIND MOUNTS (optional)
#    [STD: DISA-STIG chroot - the chroot dir MUST be root-owned and not
#     group/other writable, or sshd refuses the session.]
# =============================================================================
if [ "$USE_CHROOT" = "yes" ]; then
  install -d -m 0755 -o root -g root "$SFTP_CHROOT_BASE"
  for user in $SFTP_USERS; do
    jail="${SFTP_CHROOT_BASE}/${user}"
    install -d -m 0755 -o root -g root "$jail"          # jail root (sshd anchor)
    install -d -m 0755 -o root -g root "${jail}/data"   # bind target (mount over)
    # Mount the user's data over the jail's data/ (needs the share mounted).
    if findmnt -rn -- "${jail}/data" >/dev/null 2>&1; then
      info "Bind already active: ${jail}/data"
    elif [ "$MOUNTED" -eq 1 ] && mount "${jail}/data" 2>/dev/null; then
      log "Bind-mounted ${SFTP_DATA_BASE}/${user} -> ${jail}/data"
    else
      warn "Bind for '$user' not active yet (share not mounted). It will mount on"
      warn "  boot, or run: mount ${jail}/data"
    fi
  done
  log "Chroot jails ready under ${SFTP_CHROOT_BASE} (per-user %u)."
else
  info "USE_CHROOT=no: users are NOT chrooted; SFTP home is ${SFTP_DATA_BASE}/<user>."
fi

# =============================================================================
# 7. AUTHENTICATION  [STD: NIST IA-5 - keys PREFERRED; passwords hashed only]
#    authorized_keys live OUTSIDE any jail, root-owned, so a chrooted user can
#    never modify their own trust anchors (DISA-STIG).
# =============================================================================
AK_DIR="/etc/ssh/authorized_keys"
install -d -m 0755 -o root -g root "$AK_DIR"

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

for user in $SFTP_USERS; do
  key="$(user_var PUBKEY "$user")"
  if [ -n "$key" ]; then
    printf '%s\n' "$key" > "${AK_DIR}/${user}"
    chown root:root "${AK_DIR}/${user}"; chmod 0644 "${AK_DIR}/${user}"
    log "Installed authorized_keys for '$user'."
  else
    info "No public key supplied for '$user' (key auth skipped)."
  fi
  set_password "$user" "$(user_var PWHASH "$user")"
done

# =============================================================================
# 8. SSH / SFTP HARDENING     [STD: DISA-STIG OpenSSH SRG, NIST SC-8, CIS L2]
#    Written as a drop-in so the stock sshd_config is left intact (CM-6).
#    A single 'Match Group' rule covers ALL sftp users (scales to N users).
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

# Group password auth: on only when explicitly allowed (per-user hashes still
# gate who actually has a usable password).
grp_pw="no"
[ "$ALLOW_PASSWORD_AUTH" = "yes" ] && grp_pw="yes"

# Chroot line is included only when USE_CHROOT=yes. %u expands to the username,
# so one rule chroots every user into its own jail.
chroot_line=""
[ "$USE_CHROOT" = "yes" ] && chroot_line="    ChrootDirectory ${SFTP_CHROOT_BASE}/%u"

DROPIN="/etc/ssh/sshd_config.d/50-sftp-rhel8.conf"
install -d -m 0755 /etc/ssh/sshd_config.d
{
  cat <<EOF
# Managed by setup-sftp-rhel8.sh - do not edit by hand.
# [STD: DISA-STIG OpenSSH SRG / NIST SC-8, IA-5, AU-3 / CIS RHEL 8 L2]

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
# internal-sftp is ForceCommand'd with '-l INFO -f AUTHPRIV', logging every
# open/close/rename/remove. The global 'Subsystem sftp' line is intentionally
# NOT redefined here (the stock sshd_config defines it; a second definition
# makes 'sshd -t' fail with "Subsystem already defined").
LogLevel VERBOSE

# --- SFTP users: upload + download, chrooted (optional), SFTP-only ---------
Match Group ${SFTP_GROUP}
    ForceCommand internal-sftp -u 0027 -f AUTHPRIV -l INFO
EOF
  [ -n "$chroot_line" ] && printf '%s\n' "$chroot_line"
  cat <<EOF
    PasswordAuthentication ${grp_pw}
    AllowTcpForwarding no
    AllowStreamLocalForwarding no
    AllowAgentForwarding no
    X11Forwarding no
    PermitTunnel no
    PermitTTY no
EOF
} > "$DROPIN"
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
# 9. AUDIT RULES (optional)   [STD: NIST AU-2/AU-12, DISA-STIG]
# =============================================================================
if [ "$ENABLE_AUDIT" = "yes" ] && [ "$AUDIT_OK" -eq 1 ]; then
  ARULES="/etc/audit/rules.d/50-sftp-rhel8.rules"
  {
    printf '## Managed by setup-sftp-rhel8.sh - SFTP data-directory auditing.\n'
    printf '## [STD: NIST AU-2/AU-12 - record additions/removals/attribute changes]\n'
    printf -- '-w %s -p wa -k sftp_data\n' "$SFTP_DATA_BASE"
  } > "$ARULES"
  chmod 0640 "$ARULES"
  augenrules --load >/dev/null 2>&1 || auditctl -R "$ARULES" >/dev/null 2>&1 || \
    warn "Could not load audit rules now; they will apply on next auditd restart."
  log "Installed audit rules: $ARULES"
elif [ "$ENABLE_AUDIT" = "yes" ]; then
  warn "ENABLE_AUDIT=yes but auditd is inactive; no audit rules installed."
fi

# =============================================================================
# 10. SUMMARY
# =============================================================================
users_csv="$(printf '%s' "$SFTP_USERS" | tr ' ' ',')"
cat <<EOF

============================ SFTP SERVER READY ============================
  Group          : ${SFTP_GROUP} (gid ${SFTP_GID})
  Users          : ${users_csv}
  Data share     : ${SFTP_DATA_BASE}  (MOUNT_TYPE=${MOUNT_TYPE}${MOUNT_SOURCE:+, source ${MOUNT_SOURCE}})
  Chroot         : USE_CHROOT=${USE_CHROOT}$( [ "$USE_CHROOT" = "yes" ] && printf ' (%s/%%u, data/ bind-mounted)' "$SFTP_CHROOT_BASE" )
  Audit          : ENABLE_AUDIT=${ENABLE_AUDIT}
  SSH drop-in    : ${DROPIN}
  Listen port    : ${SFTP_PORT}
  Password auth  : ALLOW_PASSWORD_AUTH=${ALLOW_PASSWORD_AUTH} (keys preferred)

  Each user uploads AND downloads in its own directory:
      sftp ${SFTP_USERS%% *}@<host>          # then: put file / get file
  scp note: RHEL 8 scp uses the legacy protocol and will NOT work against an
  internal-sftp/nologin account. Use sftp (or scp from an OpenSSH >= 9.0 client,
  or 'scp -s' on 8.7/8.8). See ARCHITECTURE.md.

  Review any [WARN] lines above: they mark controls (FIPS, SELinux, auditd) or
  mounts that are NOT active unless enabled/reachable on this host.
==========================================================================
EOF
