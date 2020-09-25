#!/usr/bin/env bash

declare -x SIMPLESAMLPHP_HOME
[[ -z "${SIMPLESAMLPHP_HOME}" ]] && SIMPLESAMLPHP_HOME="/usr/share/simplesamlphp"

declare -x SIMPLESAMLPHP_CONF_DIR
[[ -z "${SIMPLESAMLPHP_CONF_DIR}" ]] && SIMPLESAMLPHP_CONF_DIR="/etc/simplesamlphp"


declare -x SIMPLESAMLPHP_BASEURLPATH
[[ -z "${SIMPLESAMLPHP_BASEURLPATH}" ]] && SIMPLESAMLPHP_BASEURLPATH="simplesamlphp/"

declare -x SIMPLESAMLPHP_PATH
[[ -z "${SIMPLESAMLPHP_PATH}" ]] && SIMPLESAMLPHP_PATH="$(echo ${SIMPLESAMLPHP_BASEURLPATH} | sed -E 's|^/(.*)|\1|' | sed -E 's|(.*)/|\1|')/"

__file_env 'SIMPLESAMLPHP_ADMIN_PASSWORD'
__file_env 'SIMPLESAMLPHP_SECRET_SALT'

declare -x SIMPLESAMLPHP_TECHNICAL_CONTACT_NAME
[[ -z "${SIMPLESAMLPHP_TECHNICAL_CONTACT_NAME}" ]] && SIMPLESAMLPHP_TECHNICAL_CONTACT_NAME="Administrator"

declare -x SIMPLESAMLPHP_TECHNICAL_CONTACT_EMAIL
[[ -z "${SIMPLESAMLPHP_TECHNICAL_CONTACT_EMAIL}" ]] && SIMPLESAMLPHP_TECHNICAL_CONTACT_EMAIL="na@example.org"


declare -x SIMPLESAMLPHP_LANGUAGE_DEFAULT
[[ -z "${SIMPLESAMLPHP_LANGUAGE_DEFAULT}" ]] && SIMPLESAMLPHP_LANGUAGE_DEFAULT="en"


declare -x SIMPLESAMLPHP_TIMEZONE
[[ -z "${SIMPLESAMLPHP_TIMEZONE}" ]] && SIMPLESAMLPHP_TIMEZONE="Europe/Madrid"


declare -x SIMPLESAMLPHP_ADMIN_PROTECT_INDEX_PAGE
[[ -z "${SIMPLESAMLPHP_ADMIN_PROTECT_INDEX_PAGE}" ]] && SIMPLESAMLPHP_ADMIN_PROTECT_INDEX_PAGE="false"

declare -x SIMPLESAMLPHP_ADMIN_PROTECT_METADATA
[[ -z "${SIMPLESAMLPHP_ADMIN_PROTECT_METADATA}" ]] && SIMPLESAMLPHP_ADMIN_PROTECT_METADATA="false"


declare -x SIMPLESAMLPHP_SHOW_ERRORS
[[ -z "${SIMPLESAMLPHP_SHOW_ERRORS}" ]] && SIMPLESAMLPHP_SHOW_ERRORS="true"

declare -x SIMPLESAMLPHP_ERROR_REPORTING
[[ -z "${SIMPLESAMLPHP_ERROR_REPORTING}" ]] && SIMPLESAMLPHP_ERROR_REPORTING="true"


declare -x SIMPLESAMLPHP_DEBUG_SAML
[[ -z "${SIMPLESAMLPHP_DEBUG_SAML}" ]] && SIMPLESAMLPHP_DEBUG_SAML="false"

declare -x SIMPLESAMLPHP_DEBUG_BACKTRACES
[[ -z "${SIMPLESAMLPHP_DEBUG_BACKTRACES}" ]] && SIMPLESAMLPHP_DEBUG_BACKTRACES="true"

declare -x SIMPLESAMLPHP_DEBUG_VALIDATE_XML
[[ -z "${SIMPLESAMLPHP_DEBUG_VALIDATE_XML}" ]] && SIMPLESAMLPHP_DEBUG_VALIDATE_XML="false"


declare -x SIMPLESAMLPHP_LOG_LEVEL
[[ -z "${SIMPLESAMLPHP_LOG_LEVEL}" ]] && SIMPLESAMLPHP_LOG_LEVEL="NOTICE"

declare -x SIMPLESAMLPHP_LOG_HANDLER
[[ -z "${SIMPLESAMLPHP_LOG_HANDLER}" ]] && SIMPLESAMLPHP_LOG_HANDLER="errorlog"

declare -x SIMPLESAMLPHP_LOG_FILE
[[ -z "${SIMPLESAMLPHP_LOG_FILE}" ]] && SIMPLESAMLPHP_LOG_FILE="simplesamlphp.log"


declare -x SIMPLESAMLPHP_SESSION_DURATION
[[ -z "${SIMPLESAMLPHP_SESSION_DURATION}" ]] && SIMPLESAMLPHP_SESSION_DURATION="8 * (60 * 60)"

declare -x SIMPLESAMLPHP_SESSION_DATASTORE_TIMEOUT
[[ -z "${SIMPLESAMLPHP_SESSION_DATASTORE_TIMEOUT}" ]] && SIMPLESAMLPHP_SESSION_DATASTORE_TIMEOUT="(4 * 60 * 60)"

declare -x SIMPLESAMLPHP_SESSION_STATE_TIMEOUT
[[ -z "${SIMPLESAMLPHP_SESSION_STATE_TIMEOUT}" ]] && SIMPLESAMLPHP_SESSION_STATE_TIMEOUT="(60 * 60)"

declare -x SIMPLESAMLPHP_SESSION_COOKIE_LIFETIME
[[ -z "${SIMPLESAMLPHP_SESSION_COOKIE_LIFETIME}" ]] && SIMPLESAMLPHP_SESSION_COOKIE_LIFETIME="0"

declare -x SIMPLESAMLPHP_SESSION_COOKIE_NAME
[[ -z "${SIMPLESAMLPHP_SESSION_COOKIE_NAME}" ]] && SIMPLESAMLPHP_SESSION_COOKIE_NAME="SimpleSAMLSessionID"

declare -x SIMPLESAMLPHP_SESSION_COOKIE_PATH
[[ -z "${SIMPLESAMLPHP_SESSION_COOKIE_PATH}" ]] && SIMPLESAMLPHP_SESSION_COOKIE_PATH=${SIMPLESAMLPHP_PATH}

declare -x SIMPLESAMLPHP_SESSION_COOKIE_DOMAIN
[[ -z "${SIMPLESAMLPHP_SESSION_COOKIE_DOMAIN}" ]] && SIMPLESAMLPHP_SESSION_COOKIE_DOMAIN=""

declare -x SIMPLESAMLPHP_STORE_PHPSESSION_COOKIE_NAME
[[ -z "${SIMPLESAMLPHP_STORE_PHPSESSION_COOKIE_NAME}" ]] && SIMPLESAMLPHP_STORE_PHPSESSION_COOKIE_NAME="SimpleSAML"

declare -x SIMPLESAMLPHP_SESSION_COOKIE_SECURE
[[ -z "${SIMPLESAMLPHP_SESSION_COOKIE_SECURE}" ]] && SIMPLESAMLPHP_SESSION_COOKIE_SECURE="true"

declare -x SIMPLESAMLPHP_SESSION_COOKIE_SAMESITE
[[ -z "${SIMPLESAMLPHP_SESSION_COOKIE_SAMESITE}" ]] && SIMPLESAMLPHP_SESSION_COOKIE_SAMESITE="Strict"


declare -x SIMPLESAMLPHP_STORE_PHPSESSION_COOKIE_NAME
[[ -z "${SIMPLESAMLPHP_STORE_PHPSESSION_COOKIE_NAME}" ]] && SIMPLESAMLPHP_STORE_PHPSESSION_COOKIE_NAME="SimpleSAML"

declare -x SIMPLESAMLPHP_STORE_PHPSESSION_SAVEPATH
[[ -z "${SIMPLESAMLPHP_STORE_PHPSESSION_SAVEPATH}" ]] && SIMPLESAMLPHP_STORE_PHPSESSION_SAVEPATH="/var/lib/php/sessions"

declare -x SIMPLESAMLPHP_STORE_PHPSESSION_HTTPONLY
[[ -z "${SIMPLESAMLPHP_STORE_PHPSESSION_HTTPONLY}" ]] && SIMPLESAMLPHP_STORE_PHPSESSION_HTTPONLY="true"

declare -x SIMPLESAMLPHP_STORETYPE
[[ -z "${SIMPLESAMLPHP_STORETYPE}" ]] && SIMPLESAMLPHP_STORETYPE="phpsession"

#
# SP configuration
#

declare -x SIMPLESAMLPHP_SP_NAME
[[ -z "${SIMPLESAMLPHP_SP_NAME}" ]] && SIMPLESAMLPHP_SP_NAME="sample-sp"

declare -x SIMPLESAMLPHP_SP_PRIVATE_KEY
[[ -z "${SIMPLESAMLPHP_SP_PRIVATE_KEY}" ]] && SIMPLESAMLPHP_SP_PRIVATE_KEY="example.key"

declare -x SIMPLESAMLPHP_SP_CERT
[[ -z "${SIMPLESAMLPHP_SP_CERT}" ]] && SIMPLESAMLPHP_SP_CERT="example.crt"

declare -x SIMPLESAMLPHP_SP_CERT_SUBJ
[[ -z "${SIMPLESAMLPHP_SP_CERT_SUBJ}" ]] && SIMPLESAMLPHP_SP_CERT_SUBJ="/C=ES/ST=Madrid/L=Madrid/O=My Organization/OU=My Unit/CN=simplesamlphp.example.org"

declare -x SIMPLESAMLPHP_SP_IDP_ID
[[ -z "${SIMPLESAMLPHP_SP_IDP_ID}" ]] && SIMPLESAMLPHP_SP_IDP_ID=""

declare -x SIMPLESAMLPHP_CA_FILE
[[ -z "${SIMPLESAMLPHP_CA_FILE}" ]] && SIMPLESAMLPHP_CA_FILE=""

declare -x SIMPLESAMLPHP_SP_IDP_METADATA_URL
[[ -z "${SIMPLESAMLPHP_SP_IDP_METADATA_URL}" ]] && SIMPLESAMLPHP_SP_IDP_METADATA_URL=""

declare -x SIMPLESAMLPHP_IDP
[[ -z "${SIMPLESAMLPHP_IDP}" ]] && SIMPLESAMLPHP_IDP="https://sso.example.org/"

declare -x SIMPLESAMLPHP_SIGN_REDIRECTS_REQUESTS
[[ -z "${SIMPLESAMLPHP_SIGN_REDIRECTS_REQUESTS}" ]] && SIMPLESAMLPHP_SIGN_REDIRECTS_REQUESTS="false"

declare -x SIMPLESAMLPHP_REDIRECT_VALIDATE
[[ -z "${SIMPLESAMLPHP_REDIRECT_VALIDATE}" ]] && SIMPLESAMLPHP_REDIRECT_VALIDATE="false"

declare -x SIMPLESAMLPHP_SIGN_AUTHN_REQUESTS
[[ -z "${SIMPLESAMLPHP_SIGN_AUTHN_REQUESTS}" ]] && SIMPLESAMLPHP_SIGN_AUTHN_REQUESTS="false"

declare -x SIMPLESAMLPHP_SIGN_LOGOUT_REQUESTS
[[ -z "${SIMPLESAMLPHP_SIGN_LOGOUT_REQUESTS}" ]] && SIMPLESAMLPHP_SIGN_LOGOUT_REQUESTS="false"

declare -x SIMPLESAMLPHP_ENCRYPTED_ASSERTIONS
[[ -z "${SIMPLESAMLPHP_ENCRYPTED_ASSERTIONS}" ]] && SIMPLESAMLPHP_ENCRYPTED_ASSERTIONS="false"

true