#!/usr/bin/env bash

function simplesamlphp_setup()
{

    if [[ ! -d "/etc/simplesamlphp/attributemap" ]]; then
        cp -r /usr/share/simplesamlphp/attributemap /etc/simplesamlphp
    fi

    if [[ ! -f "/etc/simplesamlphp/authsources.php" ]]; then
        cp -r /usr/share/simplesamlphp/config-templates/authsources.php /etc/simplesamlphp
    fi

    cp -r /usr/share/simplesamlphp/config-templates/config.php /etc/simplesamlphp

    simplesamlphp_configure "/etc/simplesamlphp/config.php";

}


function __simplesamlphp_set_config()
{
    local config_file="$1"
    local key="$2"
    local value="$3"
    sed -i -r -e "/^\s*['\"]$(__sed_escape_lhs "$key")['\"]/s/>(\s*)(.*)/>\1$(__sed_escape_rhs "$value"),/g" "$config_file"
}

function simplesamlphp_configure()
{
    if [[ $# -lt 1 ]]; then
        echo >&2 'Expected config file path';
        return 1;
    fi

    local config_file="$1"

    if [[ -z "$SIMPLESAMLPHP_ADMIN_PASSWORD" ]]; then
        set +e
        SIMPLESAMLPHP_ADMIN_PASSWORD=$(tr -c -d '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ' </dev/urandom | dd bs=8 count=1 2>/dev/null)
        set -e
    fi

    if [[ -z "$SIMPLESAMLPHP_SECRET_SALT" ]]; then
        set +e
        SIMPLESAMLPHP_SECRET_SALT=$(tr -c -d '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ' </dev/urandom | dd bs=32 count=1 2>/dev/null)
        set -e
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

    cp /usr/share/simplesamlphp/config-templates/apache2.conf /etc/simplesamlphp;

    if [[ ! -f "/etc/apache2/conf-available/simplesamlphp.conf" ]]; then
        ln -s /etc/simplesamlphp/apache2.conf /etc/apache2/conf-available/simplesamlphp.conf;
    fi


    simplesamlphp_setup_apache2_configure "/etc/simplesamlphp/apache2.conf" "/etc/apache2/conf-enabled/trust-proxy.conf"
}

function simplesamlphp_setup_apache2_configure()
{
    if [[ $# -lt 2 ]]; then
        echo >&2 'Expected configs files paths';
        return 1;
    fi

    local simplesamlphp_config_file="$1"
    local trustproxy_config_file="$2"

    if [[ ! -z "${SIMPLESAMLPHP_INTERNAL_PROXY_HOSTNAME+x}" ]]; then
        internal_proxy_ip=$(getent hosts $SIMPLESAMLPHP_INTERNAL_PROXY_HOSTNAME | cut -d' ' -f1)
        sed -i -E "s|RemoteIPInternalProxy(.*)|RemoteIPInternalProxy ${internal_proxy_ip}|" $simplesamlphp_config_file
        sed -i -E "s|Alias ([^ ]+) (.*)|Alias ${SIMPLESAMLPHP_PATH} \2|" $simplesamlphp_config_file
        
        echo "Define TRUST_PROXY_IP" > $trustproxy_config_file
        echo 'ErrorLogFormat "[%t] [%l] [pid %P] %F: %E: [client %a] %M"' >> $trustproxy_config_file
        echo 'LogFormat "%v:%p %a %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" vhost_combined' >> $trustproxy_config_file
        echo 'LogFormat "%a %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" combined' >> $trustproxy_config_file
    else
        cat /dev/null > $trustproxy_config_file
    fi

    if [[ ! -z "${SIMPLESAMLPHP_ENABLE_DEFAULT_VHOST+x}" ]]; then
        local begin_comment="# BEGIN SIMPLESAMLPHP"
        local end_comment="# END SIMPLESAMLPHP"
        local include_directive="Include /etc/apache2/conf-available/simplesamlphp.conf"
        local config_already_applied=$(grep "${begin_comment}" /etc/apache2/sites-available/000-default.conf)
        if [[ "$config_already_applied" == "0" ]]; then
            sed -i "/${begin_comment}/,/${end_comment}/c\${begin_comment}\n${include_directive}\n${end_comment}" /etc/apache2/sites-available/000-default.conf
        else
            sed -i "/^<\/VirtualHost>/i \\${begin_comment}\n${include_directive}\n${end_comment}" /etc/apache2/sites-available/000-default.conf;
        fi
    fi
}

function simplesamlphp_setup_php_trust_forwarded_headers()
{

    cp /usr/share/simplesamlphp/config-templates/trust-forwarded-headers.php /etc/simplesamlphp;
    simplesamlphp_setup_php_trust_forwarded_headers_configure "/etc/simplesamlphp/trust-forwarded-headers.php"
}

function simplesamlphp_setup_php_trust_forwarded_headers_configure()
{
    if [[ $# -lt 1 ]]; then
        echo >&2 'Expected config file path';
        return 1;
    fi

    local config_file="$1"

    if [[ ! -z "${SIMPLESAMLPHP_INTERNAL_PROXY_HOSTNAME+x}" ]]; then
        __simplesamlphp_set_config  $config_file "trustForwardedHeaders" "true"
    else
        __simplesamlphp_set_config  $config_file "trustForwardedHeaders" "false"
    fi

}

simplesamlphp_setup
simplesamlphp_setup_apache2
simplesamlphp_setup_php_trust_forwarded_headers