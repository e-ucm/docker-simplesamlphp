#!/usr/bin/env bash

function msmtp_setup() {
    cat<<EOF > /etc/msmtp-php.conf
account default

auth ${MSMTP_AUTH}
user ${MSMTP_USER}
${password_management}

host ${MSMTP_HOST}
port ${MSMTP_PORT}

tls ${MSMTP_TLS}
tls_starttls ${MSMTP_STARTTLS}
tls_trust_file ${MSMTP_TRUST_FILE}

from ${MSMTP_FROM}
EOF

}

msmtp_setup