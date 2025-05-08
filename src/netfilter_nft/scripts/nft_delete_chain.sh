#!/bin/sh

. "$(dirname "$0")/miniupnpd_functions.sh"

# Prerouting
$NFT delete chain $af $NAT_TABLE $PREROUTING_CHAIN
# Postrouting
$NFT delete chain $af $NAT_TABLE $POSTROUTING_CHAIN
# Filter
$NFT delete chain $af $TABLE $CHAIN
