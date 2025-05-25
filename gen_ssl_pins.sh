#!/usr/bin/env bash

if [[ $# -ne 1 ]]; then
  echo "USAGE: gen_hpkp_pins.sh host[:port]|cert"
  exit 1
fi

host="$1"
if [[ -f "$host" ]]; then
  echo -n "Subject     : " && cat "$host" | openssl x509 -subject -noout | cut -d= -f 2-
  echo -n "Expiry date : " && cat "$host" | openssl x509 -enddate -noout | cut -d= -f 2
  echo -n "sha256/"
  cat "$host" | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64
else
  java src/com/scottyab/ssl/util/SSLPinGenerator.java "$host" sha-256 debug
fi
