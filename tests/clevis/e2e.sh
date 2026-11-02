#!/usr/bin/env bash
set -euo pipefail
umask 077

: "${TANG_URL:?Set the Tang URL}"
: "${TANG_THP:?Set the independently verified signing-key thumbprint}"
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
cd "$scratch"

dpkg-query -W clevis clevis-luks jose cryptsetup-bin
config=$(jq -nc --arg url "$TANG_URL" --arg thp "$TANG_THP" '{url:$url,thp:$thp}')

printf 'Tang-Edge Clevis client test\n中文兼容验证\n' > text.in
head -c 65536 /dev/urandom > binary.in
for sample in text binary; do
  timeout 60 clevis encrypt tang "$config" < "$sample.in" > "$sample.jwe"
  timeout 60 clevis decrypt < "$sample.jwe" > "$sample.out"
  cmp "$sample.in" "$sample.out"
  printf 'PASS: %s round trip (%s bytes)\n' "$sample" "$(wc -c < "$sample.in")"
done

wrong=$(jq -nc --arg url "$TANG_URL" '{url:$url,thp:"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}')
wrong_status=0
timeout 30 clevis encrypt tang "$wrong" < text.in > rejected.jwe 2> rejected.log || wrong_status=$?
if [[ "$wrong_status" == 0 || "$wrong_status" == 124 || "$wrong_status" == 137 ]]; then
  printf 'FAIL: mismatched signing thumbprint was accepted or the test timed out\n' >&2
  exit 1
fi
http_status=$(curl --max-time 20 -sS -o /dev/null -w '%{http_code}' \
  "$TANG_URL/adv/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
if [[ "$http_status" != 404 ]] || ! grep -q 'Unable to fetch advertisement' rejected.log; then
  printf 'FAIL: fingerprint rejection was not the expected unknown-key response\n' >&2
  exit 1
fi
printf 'PASS: mismatched signing thumbprint rejected\n'

# A disposable regular file only: no host devices, loop mounts, or privileged container.
truncate -s 64M disk.img
head -c 32 /dev/urandom > recovery.key
cryptsetup luksFormat --batch-mode --type luks2 --pbkdf pbkdf2 \
  --pbkdf-force-iterations 1000 --key-file recovery.key disk.img
timeout 90 clevis luks bind -d disk.img -k recovery.key tang "$config"
timeout 60 clevis luks pass -d disk.img -s 1 > unlock.key
cryptsetup open --test-passphrase --type luks2 --key-file unlock.key disk.img
printf 'PASS: LUKS2 file binding, Tang key recovery, and cryptsetup passphrase verification\n'
printf 'ALL CLEVIS CLIENT TESTS PASSED\n'
