#!/usr/bin/env bash

function simplesamlphp_setup()
{

    if [[ ! -d "${SIMPLESAMLPHP_CONF_DIR}/attributemap" ]]; then
        cp -r "${SIMPLESAMLPHP_HOME}/attributemap" "${SIMPLESAMLPHP_CONF_DIR}"
    fi

    if [[ ! -f "${SIMPLESAMLPHP_CONF_DIR}/authsources.php" ]]; then
        cp -r "${SIMPLESAMLPHP_HOME}/config-templates/authsources.php" "${SIMPLESAMLPHP_CONF_DIR}"
    fi

    cp -r "${SIMPLESAMLPHP_HOME}/config-templates/config.php" "${SIMPLESAMLPHP_CONF_DIR}"

    simplesamlphp_configure "${SIMPLESAMLPHP_CONF_DIR}/config.php";

}


function __simplesamlphp_set_config()
{
    local config_file="$1"
    local key="$2"
    local value="$3"
    sed -i -r -e "/^\s*['\"]$(__sed_escape_lhs "$key")['\"]/s/>(\s*)(.*)/>\1$(__sed_escape_rhs "$value"),/g" "$config_file"
}

function __genpass()
{
    if [[ $# -lt 1 ]]; then
        echo >&2 'batch size missing';
        return 1;
    fi
    local batch_size="$1"
    echo $(tr -c -d '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ' </dev/urandom | dd bs=${batch_size} count=1 2>/dev/null)
}

function simplesamlphp_configure()
{
    if [[ $# -lt 1 ]]; then
        echo >&2 'Expected config file path';
        return 1;
    fi

    local config_file="$1"

    if [[ -z "$SIMPLESAMLPHP_ADMIN_PASSWORD" ]]; then
        local enabled=""
        [[ -o errexit ]] && enabled="y";
        set +e
        SIMPLESAMLPHP_ADMIN_PASSWORD=$(__genpass 8)
        [[ "${enabled}" == "y" ]] && set -e
    fi

    if [[ -z "$SIMPLESAMLPHP_SECRET_SALT" ]]; then
        local enabled=""
        [[ -o errexit ]] && enabled="y";
        set +e
        SIMPLESAMLPHP_SECRET_SALT=$(__genpass 32)
        [[ "${enabled}" == "y" ]] && set -e
    fi

    __simplesamlphp_set_config $config_file "baseurlpath" "'$SIMPLESAMLPHP_BASEURLPATH'"
    __simplesamlphp_set_config $config_file "auth.adminpassword" "'$SIMPLESAMLPHP_ADMIN_PASSWORD'"
    __simplesamlphp_set_config $config_file "secretsalt" "'$SIMPLESAMLPHP_SECRET_SALT'"

    __simplesamlphp_set_config $config_file "technicalcontact_name" "'$SIMPLESAMLPHP_TECHNICAL_CONTACT_NAME'"
    __simplesamlphp_set_config $config_file "technicalcontact_email" "'$SIMPLESAMLPHP_TECHNICAL_CONTACT_EMAIL'"

    __simplesamlphp_set_config $config_file "timezone" "'$SIMPLESAMLPHP_TIMEZONE'"

    __simplesamlphp_set_config $config_file "language.default" "'$SIMPLESAMLPHP_LANGUAGE_DEFAULT'"

    __simplesamlphp_set_config $config_file "showerrors" "$SIMPLESAMLPHP_SHOW_ERRORS"
    __simplesamlphp_set_config $config_file "errorreporting" "$SIMPLESAMLPHP_ERROR_REPORTING"
    __simplesamlphp_set_config $config_file "admin.protectindexpage" "$SIMPLESAMLPHP_ADMIN_PROTECT_INDEX_PAGE"
    __simplesamlphp_set_config $config_file "admin.protectmetadata" "$SIMPLESAMLPHP_ADMIN_PROTECT_METADATA"

    __simplesamlphp_set_config $config_file "saml" "$SIMPLESAMLPHP_DEBUG_SAML"
    __simplesamlphp_set_config $config_file "backtraces" "$SIMPLESAMLPHP_DEBUG_BACKTRACES"
    __simplesamlphp_set_config $config_file "validatexml" "$SIMPLESAMLPHP_DEBUG_VALIDATE_XML"

    __simplesamlphp_set_config $config_file "logging.level" "SimpleSAML\Logger::$SIMPLESAMLPHP_LOG_LEVEL"
    __simplesamlphp_set_config $config_file "logging.handler" "'$SIMPLESAMLPHP_LOG_HANDLER'"
    __simplesamlphp_set_config $config_file "logging.logfile" "'$SIMPLESAMLPHP_LOG_FILE'"

    __simplesamlphp_set_config $config_file "session.duration" "$SIMPLESAMLPHP_SESSION_DURATION"
    __simplesamlphp_set_config $config_file "session.datastore.timeout" "$SIMPLESAMLPHP_SESSION_DATASTORE_TIMEOUT"
    __simplesamlphp_set_config $config_file "session.state.timeout" "$SIMPLESAMLPHP_SESSION_STATE_TIMEOUT"
    __simplesamlphp_set_config $config_file "session.cookie.name" "'$SIMPLESAMLPHP_SESSION_COOKIE_NAME'"
    __simplesamlphp_set_config $config_file "session.cookie.lifetime" "$SIMPLESAMLPHP_SESSION_COOKIE_LIFETIME"
    __simplesamlphp_set_config $config_file "session.cookie.path" "'$SIMPLESAMLPHP_SESSION_COOKIE_PATH'"
    if [[ ! -z "${SIMPLESAMLPHP_SESSION_COOKIE_DOMAIN:+x}" ]]; then
        __simplesamlphp_set_config $config_file "session.cookie.domain" "'$SIMPLESAMLPHP_SESSION_COOKIE_DOMAIN'"
    fi
    __simplesamlphp_set_config $config_file "session.cookie.secure" "$SIMPLESAMLPHP_SESSION_COOKIE_SECURE"
    __simplesamlphp_set_config $config_file "session.cookie.samesite" "'$SIMPLESAMLPHP_SESSION_COOKIE_SAMESITE'"

    __simplesamlphp_set_config $config_file "session.phpsession.cookiename" "'$SIMPLESAMLPHP_STORE_PHPSESSION_COOKIE_NAME'"
    __simplesamlphp_set_config $config_file "session.phpsession.savepath" "'$SIMPLESAMLPHP_STORE_PHPSESSION_SAVEPATH'"
    __simplesamlphp_set_config $config_file "session.phpsession.httponly" "$SIMPLESAMLPHP_STORE_PHPSESSION_HTTPONLY"

    __simplesamlphp_set_config $config_file "store.type" "'$SIMPLESAMLPHP_STORETYPE'"

    # Only configure memcache options if storetype is set to memcache
    if [ "$SIMPLESAMLPHP_STORETYPE" == "memcache" ]; then
        : ${SIMPLESAMLPHP_STORE_MEMCACHE_SERVERS:="[]"}
        : ${SIMPLESAMLPHP_STORE_MEMCACHE_EXPIRES:="36 * (60 * 60)"}
        : ${SIMPLESAMLPHP_STORE_MEMCACHE_PREFIX:="SimpleSAMLphp"}
        __simplesamlphp_set_config $config_file "memcache_store.servers" "$SIMPLESAMLPHP_STORE_MEMCACHE_SERVERS"
        __simplesamlphp_set_config $config_file "memcache_store.prefix" "'$SIMPLESAMLPHP_STORE_MEMCACHE_PREFIX'"
        __simplesamlphp_set_config $config_file "memcache_store.expires" "$SIMPLESAMLPHP_STORE_MEMCACHE_EXPIRES"
    fi

    # Only configure sql options if storetype is set to sql
    if [ "$SIMPLESAMLPHP_STORETYPE" == "sql" ]; then
        : ${SIMPLESAMLPHP_STORE_SQL_DSN:="sqlite:/path/to/sqlitedatabase.sq3"}
        : ${SIMPLESAMLPHP_STORE_SQL_USERNAME:="simplesamlphp"}
        : ${SIMPLESAMLPHP_STORE_SQL_PASSWORD:="secret"}
        : ${SIMPLESAMLPHP_STORE_SQL_PREFIX:="SimpleSAMLphp"}

        __simplesamlphp_set_config $config_file "store.sql.dsn" "'$SIMPLESAMLPHP_STORE_SQL_DSN'"
        __simplesamlphp_set_config $config_file "store.sql.username" "'$SIMPLESAMLPHP_STORE_SQL_USERNAME'"
        __simplesamlphp_set_config $config_file "store.sql.password" "'$SIMPLESAMLPHP_STORE_SQL_PASSWORD'"
        __simplesamlphp_set_config $config_file "store.sql.prefix" "'$SIMPLESAMLPHP_STORE_SQL_PREFIX'"
    fi
}

function simplesamlphp_setup_apache2()
{

    cp "${SIMPLESAMLPHP_HOME}/config-templates/apache2.conf" "${SIMPLESAMLPHP_CONF_DIR}";

    if [[ ! -f "/etc/apache2/conf-available/simplesamlphp.conf" ]]; then
        ln -s "${SIMPLESAMLPHP_CONF_DIR}/apache2.conf" /etc/apache2/conf-available/simplesamlphp.conf;
    fi


    simplesamlphp_setup_apache2_configure
}

function simplesamlphp_setup_apache2_configure()
{
    local simplesamlphp_config_file="${SIMPLESAMLPHP_CONF_DIR}/apache2.conf"
    sed -i -E "s|Alias ([^ ]+) (.*)|Alias ${SIMPLESAMLPHP_PATH} \2|" $simplesamlphp_config_file

    if [[ ! -z "${SIMPLESAMLPHP_ENABLE_GLOBAL+x}" ]]; then
        a2enconf simplesamlphp
    else
        a2disconf simplesamlphp
    fi;

    local begin_comment="# BEGIN SIMPLESAMLPHP"
    local end_comment="# END SIMPLESAMLPHP"
    local include_directive="Include /etc/apache2/conf-available/simplesamlphp.conf"
    if [[ ! -z "${SIMPLESAMLPHP_ENABLE_VHOST+x}" ]]; then
        local vhost_conf="/etc/apache2/sites-available/${SIMPLESAMLPHP_ENABLE_VHOST}.conf"

        local enabled=""
        [[ -o errexit ]] && enabled="y";
        set +e
        grep "${begin_comment}" "${vhost_conf}"
        local config_already_applied=$?
        [[ "${enabled}" == "y" ]] && set -e

        if [[ $config_already_applied -ne 0 ]]; then
            sed -i "/${begin_comment}/,/${end_comment}/c${begin_comment}\n${include_directive}\n${end_comment}" "${vhost_conf}";
        else
            sed -i "/^<\/VirtualHost>/i \\${begin_comment}\n${include_directive}\n${end_comment}" "${vhost_conf}";
        fi
        echo "${SIMPLESAMLPHP_ENABLE_VHOST}" > "${SIMPLESAMLPHP_CONF_DIR}/apache2-enabled-vhost"
    else
        if [[ -f "${SIMPLESAMLPHP_CONF_DIR}/apache2-enabled-vhost" ]]; then
            local enabled=""
            [[ -o errexit ]] && enabled="y";
            set +e
            grep "${begin_comment}" "${vhost_conf}"
            local config_already_applied=$?
            [[ "${enabled}" == "y" ]] && set -e

            if [[ $config_already_applied -ne 0 ]]; then

                sed -i "/${begin_comment}/,/${end_comment}/c" "${vhost_conf}";
            fi
            rm "${SIMPLESAMLPHP_CONF_DIR}/apache2-enabled-vhost"
        fi
    fi
}

function simplesamlphp_configure_sp()
{
    if [[ ! -d "${SIMPLESAMLPHP_CONF_DIR}/certs" ]]; then
        mkdir "${SIMPLESAMLPHP_CONF_DIR}/certs"
    fi

    if [[ ! -e "${SIMPLESAMLPHP_CONF_DIR}/certs/${SIMPLESAMLPHP_SP_PRIVATE_KEY}" ]] && [[ ! -e "${SIMPLESAMLPHP_SP_PRIVATE_KEY}" ]]; then
        pushd ${SIMPLESAMLPHP_CONF_DIR}/certs > /dev/null 2>&1
        echo "Generating SSL certificates for the SimpleSAMLphp SP"
        openssl req -x509 \
            -nodes -newkey rsa:2048 -keyout ${SIMPLESAMLPHP_SP_PRIVATE_KEY} \
            -out ${SIMPLESAMLPHP_SP_CERT} \
            -days 3652 \
            -subj "${SIMPLESAMLPHP_SP_CERT_SUBJ}"

        chown root:www-data ${SIMPLESAMLPHP_SP_PRIVATE_KEY}
        chmod 640 ${SIMPLESAMLPHP_SP_PRIVATE_KEY}
        popd > /dev/null 2>&1
    fi

    if [[ ! -d "${SIMPLESAMLPHP_CONF_DIR}/metadata" ]]; then
        mkdir "${SIMPLESAMLPHP_CONF_DIR}/metadata"
    fi

    if [[ ! -e "${SIMPLESAMLPHP_CONF_DIR}/metadata/saml20-idp-remote.php" ]]; then
        echo "Generating SimpleSAMLphp Idp remote metadata"
        cat <<EOF > "${SIMPLESAMLPHP_CONF_DIR}/metadata/saml20-idp-remote.php"
<?php
\$metadata = [];
EOF
    fi

    if [[ ! -z "${SIMPLESAMLPHP_SP_IDP_METADATA_URL}" ]]; then
        local idp_configured=$(php -r "require '${SIMPLESAMLPHP_CONF_DIR}/metadata/saml20-idp-remote.php'; echo array_key_exists('${SIMPLESAMLPHP_SP_IDP_ID}', \$metadata) ? 'true' : 'false';")
        if [[ "$idp_configured" != "true" ]]; then
            local curl_extra_opts="--insecure"
            local wait_for_extra_opts="--no-check-ca"
            if [[ "${SIMPLESAMLPHP_CA_FILE:-x}" != "x" ]]; then
                curl_extra_opts="--cacert ${SIMPLESAMLPHP_CA_FILE}"
                wait_for_extra_opts="--ca-cert=${SIMPLESAMLPHP_CA_FILE}"
            fi
            wait-for "${wait_for_extra_opts}" -t 60 "${SIMPLESAMLPHP_SP_IDP_METADATA_URL}" -- echo "Getting SAML 2 IdP metadata from ${SIMPLESAMLPHP_SP_IDP_METADATA_URL}"
            local launch_bash_options=$-

            local enabled=""
            [[ -o errexit ]] && enabled="y";
            set +e
            # Using --insecure to allow to use self-signed certificates
            local tmp_metadata_file=$(mktemp)
            curl --max-time 20 -f -s ${curl_extra_opts} "${SIMPLESAMLPHP_SP_IDP_METADATA_URL}" > ${tmp_metadata_file}
            local ret_value=$?
            [[ "${enabled}" == "y" ]] && set -e

            if [[ ${ret_value} -ne 0 ]]; then
                echo "There was a problem accessing ${SIMPLESAMLPHP_SP_IDP_METADATA_URL}"
                exit 1;
            fi

            cat ${tmp_metadata_file} | php /usr/share/simplesamlphp/cli-metadata-converter.php >> "${SIMPLESAMLPHP_CONF_DIR}/metadata/saml20-idp-remote.php"
            if [[ ${ret_value} -ne 0 ]]; then
                echo "There was a problem processing SAML metadata from ${SIMPLESAMLPHP_SP_IDP_METADATA_URL}"
                exit 1;
            fi
            if [[ $launch_bash_options =~ e ]]; then
                set -e
            fi
            SIMPLESAMLPHP_SP_IDP_ID=$(php -r "require '${SIMPLESAMLPHP_CONF_DIR}/metadata/saml20-idp-remote.php'; echo array_keys(\$metadata)[0];")
        fi
        local sp_name_for_idp=${SIMPLESAMLPHP_SP_NAME:-x}
        if [[ "${sp_name_for_idp}" == "x" ]]; then
            sp_name_for_idp=$( echo "${SIMPLESAMLPHP_SP_IDP_ID}" | tr '/:.' '_')
        fi
        local sp_configured=$(php -r "require '${SIMPLESAMLPHP_CONF_DIR}/authsources.php'; echo array_key_exists('${sp_name_for_idp}', \$config) ? 'true' : 'false';")
        if [[ "$sp_configured" != "true" ]]; then
            cat <<EOF >> "${SIMPLESAMLPHP_CONF_DIR}/authsources.php"
\$config['${sp_name_for_idp}'] = [
    'saml:SP',
    'entityID' => '${sp_name_for_idp}',
    'idp' => '${SIMPLESAMLPHP_SP_IDP_ID}',
    'privatekey' => '${SIMPLESAMLPHP_SP_PRIVATE_KEY}',
    'certificate' => '${SIMPLESAMLPHP_SP_CERT}',
    'sign.authnrequest' => ${SIMPLESAMLPHP_SIGN_AUTHN_REQUESTS},
    'sign.logout' => ${SIMPLESAMLPHP_SIGN_LOGOUT_REQUESTS},
    'assertion.encryption' => ${SIMPLESAMLPHP_ENCRYPTED_ASSERTIONS},
    'redirect.sign' => ${SIMPLESAMLPHP_SIGN_REDIRECTS_REQUESTS},
    'redirect.validate' => ${SIMPLESAMLPHP_REDIRECT_VALIDATE},
];
EOF
        fi
    fi
}

simplesamlphp_setup
simplesamlphp_setup_apache2
simplesamlphp_configure_sp