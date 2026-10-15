#!/bin/bash
# Offer Kerberos (GSSAPI) for sending mail on port 465 (smtps) only.
#
# Why: mailboxes the AD sync creates get a random password nobody knows. Reading mail already
# works with Kerberos (Dovecot IMAP), but Postfix hides GSSAPI on every port
# (smtpd_sasl_mechanism_filter = !external, !gssapi, ...), so sending needs that password.
#
# What it changes: one master.cf override for the smtps service, which drops "!gssapi" from the
# filter. Port 587 (submission) and 25 keep the global filter, so .NET SmtpClient (STARTTLS on 587,
# it cannot do port 465) still never sees GSSAPI. Dovecot already has the gssapi mechanism and the
# smtp/mail.example.com key in /etc/dovecot/krb5.keytab, so nothing changes there.
#
# Run as root on mail.example.com:  bash smtp-kerberos.sh
# Undo:                          bash /root/backup-smtp-krb-<ts>/rollback.sh
set -euo pipefail

TS=$(date +%Y%m%d-%H%M%S)
BK=/root/backup-smtp-krb-$TS
FILTER='!external,static:rest'           # global value minus "!gssapi"; no spaces: master.cf -o values can't have any
log() { echo "$(date '+%F %T') $*"; }

ehlo_auth() {   # $1 = port; prints the AUTH line the server advertises after TLS
    # not 127.0.0.1: it is in $mynetworks = smtpd_sasl_exceptions_networks, which never sees AUTH
    local opts=(-connect 10.0.12.5:"$1" -servername mail.example.com -quiet -ign_eof)
    [ "$1" = 587 ] && opts+=(-starttls smtp)
    { sleep 2; printf 'EHLO selftest.example.com\r\n'; sleep 2; printf 'QUIT\r\n'; } |
        timeout 15 openssl s_client "${opts[@]}" 2>/dev/null | tr -d '\r' | grep -i '^250[- ]AUTH' | head -1
}

mkdir -p "$BK"
cp -a /etc/postfix/master.cf "$BK/master.cf"
cat > "$BK/rollback.sh" <<EOF
#!/bin/bash
cp -a $BK/master.cf /etc/postfix/master.cf && postfix check && postfix reload && echo "rolled back to $BK/master.cf"
EOF
chmod +x "$BK/rollback.sh"
log "backup in $BK"

log "before: 465 -> $(ehlo_auth 465)"
log "before: 587 -> $(ehlo_auth 587)"

postconf -P "smtps/inet/smtpd_sasl_mechanism_filter=$FILTER"
postfix check
postfix reload
sleep 3

A465=$(ehlo_auth 465); A587=$(ehlo_auth 587)
log "after:  465 -> $A465"
log "after:  587 -> $A587"

fail=""
grep -qi gssapi <<<"$A465" || fail+=" 465 does not offer GSSAPI;"
grep -qi plain  <<<"$A465" || fail+=" 465 lost PLAIN;"
grep -qi gssapi <<<"$A587" && fail+=" 587 offers GSSAPI;"
grep -qi plain  <<<"$A587" || fail+=" 587 lost PLAIN;"

if [ -n "$fail" ]; then
    log "SELF-TEST FAILED:$fail restoring"
    bash "$BK/rollback.sh"
    exit 1
fi
log "OK. Kerberos sending is offered on 465 only. Undo: bash $BK/rollback.sh"
log "Watch: grep -E 'smtps/smtpd.*(GSSAPI|sasl_method=GSSAPI)' /var/log/mail.log"
