#!/bin/bash

master=$1
if [ -z "$master" ]; then
    echo "ERROR: master is not set"
    echo
    echo "usage: $0 master-fqdn domain"
    exit 0;
fi

PASSWORD="SomeCApassword"
DBDIR="${master}-nssdb"
PWDFILE="$DBDIR/pwdfile.txt"
NOISE="/etc/passwd"

domain=$2
if [ -z "$domain" ]; then
    echo "ERROR: domain is not set"
    echo
    echo "usage: $0 master-fqdn domain"
    exit 0;
fi

if [ ! -f "${master}-ipa.csr" ]; then
    echo "ERROR: ${master}-ipa.csr missing"
    exit 1;
fi

ROOT_KEY_ID=0x$(dd if=/dev/urandom bs=20 count=1 | xxd -p)
IPA_CA_KEY_ID=0x$(dd if=/dev/urandom bs=20 count=1 | xxd -p)

rm -rf "$DBDIR"
mkdir "$DBDIR"
echo "$PASSWORD" > "$PWDFILE"
certutil -N -d "$DBDIR" -f "$PWDFILE"
echo -e "0\n1\n5\n6\n9\ny\ny\n\ny\n${ROOT_KEY_ID}\nn\n" \
  | certutil -d "$DBDIR"  -f "$PWDFILE" -S -z "$NOISE" -n ca -x -t C,C,C \
    -s "CN=PRIMARY,O=$domain" -x -1 -2 --extSKID

openssl req -outform der -in "${master}-ipa.csr" -out "$DBDIR/req.csr"
echo -e "0\n1\n5\n6\n9\ny\ny\n\ny\ny\n${ROOT_KEY_ID}\n\n\nn\n${IPA_CA_KEY_ID}\nn\n" \
  | certutil -d "$DBDIR" -f "$PWDFILE" -C -z "$NOISE" -c ca \
    -i "$DBDIR/req.csr" -o "$DBDIR/external.cer" -1 -2 -3 --extSKID

openssl x509 -inform der -in "$DBDIR/external.cer" -out "$DBDIR/external.pem"
certutil -L -n ca -d "$DBDIR" -a > "$DBDIR/ca.crt"
cat "$DBDIR/external.pem" "$DBDIR/ca.crt" > "$DBDIR/chain.crt"

cp "$DBDIR/chain.crt" "${master}-chain.crt"
