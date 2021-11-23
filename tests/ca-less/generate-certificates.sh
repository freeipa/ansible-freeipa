#!/usr/bin/env bash

ROOT_CA_DIR="certificates/root-ca"
DIRSRV_CERTS_DIR="certificates/dirsrv"
HTTPD_CERTS_DIR="certificates/httpd"
PKINIT_CERTS_DIR="certificates/pkinit"
PKCS12_PASSWORD="SomePKCS12password"

# generate_ipa_pkcs12_certificate \
#    $cert_name $ipa_fqdn $certs_dir $root_ca_cert $root_ca_private_key extensions_file extensions_name
function generate_ipa_pkcs12_certificate {

    cert_name=$1
    ipa_fqdn=$2
    certs_dir=$3
    root_ca_cert=$4
    root_ca_private_key=$5
    extensions_file=$6
    extensions_name=$7

    # Generate CSR and private key
    openssl req -new -newkey rsa:4096 -nodes \
        -subj "/C=US/ST=Test/L=Testing/O=Default/CN=${ipa_fqdn}" \
        -keyout "${certs_dir}/private.key" \
        -out "${certs_dir}/request.csr"

    # Sign CSR to generate PEM certificate
    if [ -z "${extensions_file}" ]; then
        openssl x509 -req -days 365 -sha256 \
            -CAcreateserial \
            -CA "${root_ca_cert}" \
            -CAkey "${root_ca_private_key}" \
            -in "${certs_dir}/request.csr" \
            -out "${certs_dir}/cert.pem"
    else
        openssl x509 -req -days 365 -sha256 \
            -CAcreateserial \
            -CA "${ROOT_CA_DIR}/cert.pem" \
            -CAkey "${ROOT_CA_DIR}/private.key" \
            -extfile "${extensions_file}" \
            -extensions "${extensions_name}" \
            -in "${certs_dir}/request.csr" \
            -out "${certs_dir}/cert.pem"
    fi

    # Convert certificate to PKCS12 format
    openssl pkcs12 -export \
        -name "${cert_name}" \
        -certfile "${root_ca_cert}" \
        -in "${certs_dir}/cert.pem" \
        -inkey "${certs_dir}/private.key" \
        -passout "pass:${PKCS12_PASSWORD}" \
        -out "${certs_dir}/cert.p12"
}

# generate_ipa_pkcs12_certificates $ipa_fqdn $ipa_domain
function generate_ipa_pkcs12_certificates {

    host=$1
    if [ -z "$host" ]; then
        echo "ERROR: ipa-host-fqdn is not set"
        echo
        echo "usage: $0 create ipa-host-fqdn domain"
        exit 0;
    fi

    domain=$2
    if [ -z "$domain" ]; then
        echo "ERROR: domain is not set"
        echo
        echo "usage: $0 create ipa-host-fqdn domain"
        exit 0;
    fi

    # Generate certificates folder structure
    mkdir -p "${ROOT_CA_DIR}"
    mkdir -p "${DIRSRV_CERTS_DIR}/$host"
    mkdir -p "${HTTPD_CERTS_DIR}/$host"
    mkdir -p "${PKINIT_CERTS_DIR}/$host"

    # Generate root CA
    if [ ! -f "${ROOT_CA_DIR}/private.key" ]; then
        openssl genrsa \
                -out "${ROOT_CA_DIR}/private.key" 4096

        openssl req -new -x509 -sha256 -nodes -days 3650 \
                -subj "/C=US/ST=Test/L=Testing/O=Default" \
                -key "${ROOT_CA_DIR}/private.key" \
                -out "${ROOT_CA_DIR}/cert.pem"
    fi

    # Generate a certificate for the Directory Server
    if [ ! -f "${DIRSRV_CERTS_DIR}/$host/cert.pem" ]; then
        generate_ipa_pkcs12_certificate \
            "dirsrv-cert" \
            "$host" \
            "${DIRSRV_CERTS_DIR}/$host" \
            "${ROOT_CA_DIR}/cert.pem" \
            "${ROOT_CA_DIR}/private.key"
    fi

    # Generate a certificate for the Apache server
    if [ ! -f "${HTTPD_CERTS_DIR}/$host/cert.pem" ]; then
        generate_ipa_pkcs12_certificate \
            "httpd-cert" \
            "$host" \
            "${HTTPD_CERTS_DIR}/$host" \
            "${ROOT_CA_DIR}/cert.pem" \
            "${ROOT_CA_DIR}/private.key"
    fi

    # Generate a certificate for the KDC PKINIT
    if [ ! -f "${PKINIT_CERTS_DIR}/$host/cert.pem" ]; then
        export REALM=${domain^^}

        generate_ipa_pkcs12_certificate \
            "pkinit-cert" \
            "$host" \
            "${PKINIT_CERTS_DIR}/$host" \
            "${ROOT_CA_DIR}/cert.pem" \
            "${ROOT_CA_DIR}/private.key" \
            "${PKINIT_CERTS_DIR}/extensions.conf" \
            "kdc_cert"
    fi
}

# delete_ipa_pkcs12_certificates $ipa_fqdn
function delete_ipa_pkcs12_certificates {

    host=$1
    if [ -z "$host" ]; then
        echo "ERROR: ipa-host-fqdn is not set"
        echo
        echo "usage: $0 delete ipa-host-fqdn"
        exit 0;
    fi

    rm -f certificates/*/"$host"/*
    rm -f "${ROOT_CA_DIR}"/*
}

# Entrypoint
case "$1" in
  create)
    generate_ipa_pkcs12_certificates "$2" "$3"
    ;;
  delete)
    delete_ipa_pkcs12_certificates "$2"
    ;;
  *)
    echo $"Usage: $0 {create|delete}"
    ;;
esac
