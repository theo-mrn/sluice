#!/bin/sh
# An event command for sluice (--event-command) that sends an event to a webhook: a chat, a pager, anything that
# takes an HTTP POST. sluice runs it for each event of its filter, with the line of the log on the standard input
# and the name of the event in $SLUICE_EVENT.
#
#   sluice ... --event-command 'WEBHOOK_URL=https://hooks.example.com/abc /usr/local/share/sluice/webhook.sh' \
#              --event-filter alert,kill,confirm_pending
#
# WEBHOOK_URL      where to post (required)
# WEBHOOK_FORMAT   json (default: the line itself), slack or mattermost ({"text": ...}), discord ({"content": ...})
# WEBHOOK_SECRET   when set, the body is signed: X-Sluice-Signature: sha256=<hex hmac of the body>
# WEBHOOK_ADMIN    http://127.0.0.1:9100 and WEBHOOK_TOKEN_FILE: for confirm_pending, the question is fetched from the
#                  admin listener and put in the message (the rows are not in the event: they are only there)
#
# It needs curl, and openssl for the signature. It sends one request and exits: sluice does not wait for it, kills
# it after 15 seconds, and discards what it prints.

set -eu

line=$(cat)
event=${SLUICE_EVENT:-event}
: "${WEBHOOK_URL:?WEBHOOK_URL is not set}"

# the fields that make a readable message, taken from the line without a JSON tool
field() { printf '%s' "$line" | sed -n "s/.*\"$1\":\"\\([^\"]*\\)\".*/\\1/p" | head -n 1; }
number() { printf '%s' "$line" | sed -n "s/.*\"$1\":\\([0-9][0-9]*\\).*/\\1/p" | head -n 1; }

user=$(field user)
rule=$(field rule)
text="sluice: $event"
[ -n "$rule" ] && text="$text, rule $rule"
[ -n "$user" ] && text="$text, user $user"
case $event in
confirm_pending)
    tag=$(field tag)
    question=$(field question)
    text="$text: $tag waits for an answer (id $question)"
    if [ -n "${WEBHOOK_ADMIN:-}" ] && [ -n "$question" ]; then
        token=$(cat "${WEBHOOK_TOKEN_FILE:?WEBHOOK_TOKEN_FILE is not set}")
        detail=$(curl -fsS --max-time 5 -H "Authorization: Bearer $token" "$WEBHOOK_ADMIN/pending/$question" || true)
        [ -n "$detail" ] && text="$text
$detail

answer: curl -X POST -H 'Authorization: Bearer ...' $WEBHOOK_ADMIN/confirm/$question/yes   (or /no)"
    fi
    ;;
esac

tab=$(printf '\t')
cr=$(printf '\r')
# a JSON string: backslash, quote, tab, carriage return and newline escaped
escape() {
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e "s/$tab/\\\\t/g" -e "s/$cr/\\\\r/g" |
        awk 'NR > 1 { printf "%s", "\\n" } { printf "%s", $0 }'
}

case ${WEBHOOK_FORMAT:-json} in
slack | mattermost) body="{\"text\":\"$(escape "$text")\"}" ;;
discord) body="{\"content\":\"$(escape "$text")\"}" ;;
*) body=$line ;;
esac

if [ -n "${WEBHOOK_SECRET:-}" ]; then
    sig=$(printf '%s' "$body" | openssl dgst -sha256 -hmac "$WEBHOOK_SECRET" | sed 's/^.* //')
    exec curl -fsS --max-time 10 -X POST -H 'Content-Type: application/json' -H "X-Sluice-Event: $event" \
        -H "X-Sluice-Signature: sha256=$sig" --data-binary "$body" "$WEBHOOK_URL"
fi
exec curl -fsS --max-time 10 -X POST -H 'Content-Type: application/json' -H "X-Sluice-Event: $event" \
    --data-binary "$body" "$WEBHOOK_URL"
