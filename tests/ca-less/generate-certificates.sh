#!/usr/bin/env bash

CERTIFICATES="certificates"
ROOT_CA_DIR="${CERTIFICATES}/root-ca"
DIRSRV_CERTS_DIR="${CERTIFICATES}/dirsrv"
HTTPD_CERTS_DIR="${CERTIFICATES}/httpd"
PKINIT_CERTS_DIR="${CERTIFICATES}/pkinit"
EXTENSIONS_CONF="${CERTIFICATES}/extensions.conf"
PKINIT_EXTENSIONS_CONF="${CERTIFICATES}/pkinit-extensions.conf"
PKCS12_PASSWORD="SomePKCS12password"

# create_ca \
#    $domain_name
function create_ca {

    domain_name=$1
    if [ -z "${domain_name}" ]; then
        echo "ERROR: domain is not set"
        echo
        echo "usage: $0 ca <domain>"
        exit 0;
    fi
    realm=${domain_name^^}

    export REALM_NAME=${realm}

    # Create certificates folder structure
    mkdir -p "${ROOT_CA_DIR}"

    # Create root CA
    if [ ! -f "${ROOT_CA_DIR}/private.key" ]; then
        # create aes encrypted private key
        openssl genrsa -out "${ROOT_CA_DIR}/private.key" 4096

        # create certificate, 1826 days = 5 years
        openssl req -x509 -new -nodes -sha256 -days 1826 \
                -subj "/C=US/ST=Test/L=Testing/O=Default/CN=Test Root CA" \
                -key "${ROOT_CA_DIR}/private.key" \
                -out "${ROOT_CA_DIR}/cert.pem"
    fi
}

# create_host_pkcs12_certificate \
#    $cert_name $certs_dir $root_ca_cert $extensions_file
function create_host_pkcs12_certificate {

    cert_name=$1
    certs_dir=$2
    root_ca_cert=$3
    extensions_file=$4

    # Create CSR and private key
    openssl req -new -nodes -newkey rsa:4096 \
                -subj "/C=US/ST=Test/L=Testing/O=Default/CN=${cert_name}" \
                -keyout "${certs_dir}/private.key" \
                -out "${certs_dir}/request.csr"

    # Sign CSR to create PEM certificate
    openssl x509 -req -days 1460 -sha256 -CAcreateserial \
                -CAkey "${ROOT_CA_DIR}/private.key" \
                -CA "${root_ca_cert}" \
                -in "${certs_dir}/request.csr" \
                -out "${certs_dir}/cert.pem" \
                -extfile "${extensions_file}"

    # Convert certificate to PKCS12 format
    openssl pkcs12 -export \
            -name "${cert_name}" \
            -certfile "${root_ca_cert}" \
            -passout "pass:${PKCS12_PASSWORD}" \
            -inkey "${certs_dir}/private.key" \
            -in "${certs_dir}/cert.pem" \
            -out "${certs_dir}/cert.p12"
}

# create_ipa_pkcs12_certificates \
#    $host_fqdn $domain_name
function create_host_certificates {

    host_fqdn=$1
    if [ -z "${host_fqdn}" ]; then
        echo "ERROR: host-fqdn is not set"
        echo
        echo "usage: $0 create <host-fqdn> [<domain>]"
        exit 0;
    fi

    domain_name=$2
    [ -z "${domain_name}" ] && domain_name=${host_fqdn#*.*}
    if [ -z "${domain_name}" ]; then
        echo "ERROR: domain is not set and can not be created from host fqdn"
        echo
        echo "usage: $0 create <host-fqdn> [<domain>]"
        exit 0;
    fi
    realm=${domain_name^^}

    export HOST_FQDN=${host_fqdn}
    export REALM_NAME=${realm}

    if [ ! -f "${ROOT_CA_DIR}/private.key" ]; then
        create_ca "${domain_name}"
    fi

    # Create certificates folder structure
    mkdir -p "${DIRSRV_CERTS_DIR}/${host_fqdn}"
    mkdir -p "${HTTPD_CERTS_DIR}/${host_fqdn}"
    mkdir -p "${PKINIT_CERTS_DIR}/${host_fqdn}"

    # Create a certificate for the Directory Server
    if [ ! -f "${DIRSRV_CERTS_DIR}/${host_fqdn}/cert.pem" ]; then
        create_host_pkcs12_certificate \
            "dirsrv-cert" \
            "${DIRSRV_CERTS_DIR}/${host_fqdn}" \
            "${ROOT_CA_DIR}/cert.pem" \
            "${EXTENSIONS_CONF}"
    fi

    # Create a certificate for the Apache server
    if [ ! -f "${HTTPD_CERTS_DIR}/${host_fqdn}/cert.pem" ]; then
        create_host_pkcs12_certificate \
            "httpd-cert" \
            "${HTTPD_CERTS_DIR}/${host_fqdn}" \
            "${ROOT_CA_DIR}/cert.pem" \
            "${EXTENSIONS_CONF}"
    fi

    # Create a certificate for the KDC PKINIT
    if [ ! -f "${PKINIT_CERTS_DIR}/${host_fqdn}/cert.pem" ]; then
        create_host_pkcs12_certificate \
            "pkinit-cert" \
            "${PKINIT_CERTS_DIR}/${host_fqdn}" \
            "${ROOT_CA_DIR}/cert.pem" \
            "${PKINIT_EXTENSIONS_CONF}"
    fi
}

# delete_host_certificates \
#     $host_fqdn
function delete_host_certificates {

    host_fqdn=$1
    if [ -z "${host_fqdn}" ]; then
        echo "ERROR: host-fqdn is not set"
        echo
        echo "usage: $0 delete <host-fqdn>"
        exit 0;
    fi

    rm -rf certificates/*/"${host_fqdn}"/
}

# cleanup \
#     $host_fqdn
function cleanup {

    rm -rf certificates/*/
}

# Entrypoint
case "$1" in
  ca)
    create_ca "$2"
    ;;
  create)
    create_host_certificates "$2" "$3"
    ;;
  delete)
    delete_host_certificates "$2"
    ;;
  cleanup)
    cleanup
    ;;
  *)
    echo $"Usage: $0 {create|delete|ca|cleanup}"
    ;;
esac
