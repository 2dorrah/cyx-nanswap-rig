#!/usr/bin/env bash
set -euo pipefail
: "${NANO_ADDRESS:?Set NANO_ADDRESS to your Nano payout address}"
exec ./xmrig -o xmrig.nanswap.com:3333 -a rx/0 -k -u "$NANO_ADDRESS" -p x
