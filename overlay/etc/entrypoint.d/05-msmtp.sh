#!/usr/bin/env bash

declare -x MSMTP_AUTH
[[ -z "${MSMTP_AUTH}" ]] && MSMTP_AUTH="off"

declare -x MSMTP_USER
[[ -z "${MSMTP_USER}" ]] && MSMTP_USER="user"

declare -x MSMTP_PASSWORD_MANAGEMENT
if [[ -z "${MSMTP_PASSWORD_MANAGEMENT}" ]]; then
    if [[ ! -z "${MSMTP_PASSWORD_EVAL+x}" ]]; then
        MSMTP_PASSWORD_MANAGEMENT="passwordeval ${MSMTP_PASSWORD_EVAL}"
    else
        __file_env 'MSMTP_PASSWORD' 'password'
        MSMTP_PASSWORD_MANAGEMENT="password ${MSMTP_PASSWORD}"
    fi
fi

declare -x MSMTP_HOST
[[ -z "${MSMTP_HOST}" ]] && MSMTP_HOST="localhost"

declare -x MSMTP_PORT
[[ -z "${MSMTP_PORT}" ]] && MSMTP_PORT="25"

declare -x MSMTP_AUTH
[[ -z "${MSMTP_AUTH}" ]] && MSMTP_AUTH="off"

declare -x MSMTP_TLS
[[ -z "${MSMTP_TLS}" ]] && MSMTP_TLS="off"

declare -x MSMTP_STARTTLS
[[ -z "${MSMTP_STARTTLS}" ]] && MSMTP_STARTTLS="off"

declare -x MSMTP_TRUST_FILE
[[ -z "${MSMTP_TRUST_FILE}" ]] && MSMTP_TRUST_FILE="system"

declare -x MSMTP_FROM
[[ -z "${MSMTP_FROM}" ]] && MSMTP_FROM="no-reply@example.net"

true