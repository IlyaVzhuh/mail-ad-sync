#!/bin/bash
# Switch AD -> mail sync from "link" to "enforce" on mail.example.com (run as root, from the folder
# that also holds the new ./ad-mail-sync):
#   1. Dovecot refuses login (IMAP/POP/SMTP-AUTH, password and Kerberos) for rows in mailbox_block;
#      delivery (lda/lmtp) and doveadm still work.
#   2. Self-test on test-krb@example.com: blocked -> login refused, mail still delivered; unblocked -> login ok.
#      Any failure -> Dovecot config restored automatically, nothing blocked.
#   3. One mass run: blocks all AD-disabled users (approved: all, ~320), then mode=enforce for the timer.
# Rollback afterwards: bash /root/backup-enforce-<ts>/rollback.sh
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
TS=$(date +%Y%m%d-%H%M%S)
BK=/root/backup-enforce-$TS
SQLCONF=/etc/dovecot/dovecot-sql.conf.ext
SYNCCONF=/etc/ad-mail-sync.conf
TEST=test-krb@example.com
TESTPW=$(cat /root/.test-krb-password)

say()  { echo "[$(date +%T)] $*"; }
fail() { say "FAIL: $*"; exit 1; }

[ "$(id -u)" = 0 ] || fail "run as root"
[ -f "$HERE/ad-mail-sync" ] || fail "new ad-mail-sync not next to this script"
grep -q '^password_query' "$SQLCONF" || fail "$SQLCONF looks wrong"
grep -q 'mailbox_block' "$SQLCONF" && fail "$SQLCONF already references mailbox_block - already applied?"

# ---------- backup + rollback script ----------
mkdir -p "$BK"
cp -a "$SQLCONF" "$SYNCCONF" /usr/local/sbin/ad-mail-sync "$BK/"
mysqldump postfix mailbox_block ad_sync_state > "$BK/tables.sql"
cat > "$BK/rollback.sh" <<EOF
#!/bin/bash
# Undo enforce.sh run $TS
set -x
systemctl stop ad-mail-sync.timer
cp -a $BK/$(basename $SQLCONF) $SQLCONF
cp -a $BK/$(basename $SYNCCONF) $SYNCCONF
cp -a $BK/ad-mail-sync /usr/local/sbin/ad-mail-sync
doveadm reload
mysql postfix -e "DELETE FROM mailbox_block WHERE reason='ad_disabled' AND since >= '$(date -u +%F\ %T)'"
systemctl start ad-mail-sync.timer
EOF
chmod 700 "$BK/rollback.sh"
say "backup + rollback script in $BK"

restore_dovecot() {
    say "restoring Dovecot config"
    cp -a "$BK/$(basename $SQLCONF)" "$SQLCONF"
    doveadm reload
    mysql postfix -e "DELETE FROM mailbox_block WHERE username='$TEST' AND reason='manual'"
    systemctl start ad-mail-sync.timer
}

# ---------- 1. new sync script + config ----------
systemctl stop ad-mail-sync.timer
install -m 755 "$HERE/ad-mail-sync" /usr/local/sbin/ad-mail-sync
grep -q '^no_create' "$SYNCCONF" || sed -i '/^max_blocks/a no_create = vpn-phone' "$SYNCCONF"
say "ad-mail-sync updated, no_create = $(grep '^no_create' $SYNCCONF | cut -d= -f2)"

# ---------- 2. Dovecot queries ----------
python3 - "$SQLCONF" <<'PY'
import re, sys
p = sys.argv[1]; s = open(p).read()
NB = "NOT EXISTS (SELECT 1 FROM mailbox_block b WHERE b.username = m.username)"
pw = """password_query = SELECT m.password, \\
  (SELECT GROUP_CONCAT(DISTINCT CONCAT(a.sam, '@CORP.EXAMPLE.COM')) FROM ad_user a WHERE a.username = m.username) AS k5principals \\
  FROM mailbox m WHERE m.username = '%u' \\
  AND """ + NB + "\n"
# blocked users still resolve for delivery (lda/lmtp) and admin tools (doveadm)
us = """user_query = SELECT m.username AS user, 1024 AS uid, 1024 AS gid FROM mailbox m WHERE m.username = '%u' \\
  AND ('%s' IN ('lda','lmtp','doveadm') OR """ + NB + """) \\
  UNION ALL \\
  SELECT m.username, 1024, 1024 FROM ad_user a JOIN mailbox m ON m.username = a.username \\
  WHERE '%d' = 'corp.example.com' AND a.sam = '%n' \\
  AND """ + NB + """ \\
  LIMIT 1
"""
# replace each (multi-line, backslash-continued) query
def repl(s, key, new):
    pat = re.compile(r"^" + key + r"\s*=.*?(?<!\\)\n", re.S | re.M)
    s, n = pat.subn(lambda m: new, s, count=1)
    assert n == 1, key
    return s
s = repl(s, "password_query", pw)
s = repl(s, "user_query", us)
open(p, "w").write(s)
PY
doveconf -n >/dev/null || { restore_dovecot; fail "doveconf rejects new config"; }
doveadm reload
sleep 2
say "Dovecot queries updated and reloaded"

# ---------- 3. self-test on $TEST ----------
auth_ok() { doveadm auth test -x service=imap "$TEST" "$TESTPW" >/dev/null 2>&1; }
TOKEN="enforce-test-$TS"

auth_ok || { restore_dovecot; fail "unblocked $TEST cannot log in"; }
say "test 1 OK: unblocked login works"

mysql postfix -e "INSERT INTO mailbox_block (username, reason, since, note) VALUES ('$TEST','manual',UTC_TIMESTAMP(),'enforce.sh self-test')"
if auth_ok; then restore_dovecot; fail "BLOCKED $TEST can still log in"; fi
say "test 2 OK: blocked login refused"

doveadm user -x service=imap "$TEST" >/dev/null 2>&1 && { restore_dovecot; fail "blocked $TEST still resolves for imap (Kerberos path)"; }
doveadm user -x service=lda  "$TEST" >/dev/null 2>&1 || { restore_dovecot; fail "blocked $TEST does not resolve for delivery"; }
say "test 3 OK: userdb refuses imap, allows lda"

printf 'Subject: %s\n\nblocked-delivery test\n' "$TOKEN" | /usr/sbin/sendmail "$TEST"
for i in $(seq 30); do
    doveadm search -u "$TEST" mailbox INBOX subject "$TOKEN" 2>/dev/null | grep -q . && break
    sleep 2
done
doveadm search -u "$TEST" mailbox INBOX subject "$TOKEN" 2>/dev/null | grep -q . \
    || { restore_dovecot; fail "mail to blocked $TEST was NOT delivered (check mailq)"; }
doveadm expunge -u "$TEST" mailbox INBOX subject "$TOKEN" || true
say "test 4 OK: mail to a blocked mailbox is still delivered"

mysql postfix -e "DELETE FROM mailbox_block WHERE username='$TEST' AND reason='manual'"
auth_ok || { restore_dovecot; fail "$TEST cannot log in after unblock"; }
say "test 5 OK: unblock restores login"

# ---------- 4. mass block (one time) + switch the timer to enforce ----------
before=$(mysql postfix -Ne "SELECT COUNT(*) FROM mailbox_block")
/usr/local/sbin/ad-mail-sync --mode enforce --allow-mass-block 2>&1 | tee "$BK/first-enforce-run.log" | tail -3
after=$(mysql postfix -Ne "SELECT COUNT(*) FROM mailbox_block")
say "mailbox_block: $before -> $after rows"

sed -i 's/^mode *= *link/mode = enforce/' "$SYNCCONF"
grep -q '^mode = enforce' "$SYNCCONF" || fail "could not set mode = enforce in $SYNCCONF (blocks are in place; timer still stopped)"
systemctl start ad-mail-sync.timer

sample=$(mysql postfix -Ne "SELECT username FROM mailbox_block WHERE reason='ad_disabled' LIMIT 1")
[ -n "$sample" ] && ! doveadm user -x service=imap "$sample" >/dev/null 2>&1 && say "check OK: $sample is refused"
say "DONE. mode=enforce, timer running. Rollback: bash $BK/rollback.sh"
