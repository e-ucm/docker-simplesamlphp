#!/usr/bin/env bash

TRUSTPROXY_CONFIG="/etc/apache2/conf-available/00-trustproxy.conf"

function remoteip_setup_apache2()
{
    remoteip_setup_apache2_configure
}

function remoteip_setup_apache2_configure()
{

    local trustproxy_ip="${APACHE2_REMOTEIP_TRUSTPROXY_IP}"
    if [[ -z "${trustproxy_ip}" ]]; then
        if [[ ! -z "${APACHE2_REMOTEIP_TRUSTPROXY_HOSTNAME+x}" ]]; then
            trustproxy_ip=$(getent hosts $APACHE2_REMOTEIP_TRUSTPROXY_HOSTNAME | cut -d' ' -f1)
        fi
    fi

    if [[ ! -z "${trustproxy_ip+x}" ]]; then
        echo "Define TRUST_PROXY_IP" > $TRUSTPROXY_CONFIG
        echo "RemoteIPInternalProxy ${trustproxy_ip}" >> $TRUSTPROXY_CONFIG
        echo 'ErrorLogFormat "[%t] [%l] [pid %P] %F: %E: [client %a] %M"' >> $TRUSTPROXY_CONFIG
        echo 'LogFormat "%v:%p %a %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" vhost_combined' >> $TRUSTPROXY_CONFIG
        echo 'LogFormat "%a %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" combined' >> $TRUSTPROXY_CONFIG
        a2enconf 00-trustproxy
        find /etc/apache2 -type f -name '*.conf' -exec sed -ri 's/([[:space:]]*LogFormat[[:space:]]+"[^"]*)%h([^"]*")/\1%a\2/g' '{}' +
    else
        cat /dev/null > $TRUSTPROXY_CONFIG
        find /etc/apache2 -type f -name '*.conf' -exec sed -ri 's/([[:space:]]*LogFormat[[:space:]]+"[^"]*)%a([^"]*")/\1%h\2/g' '{}' +
        a2disconf 00-trustproxy
    fi
}

function remoteip_setup_php_trust_forwarded_headers()
{

    cp "${SIMPLESAMLPHP_HOME}/config-templates/trust-forwarded-headers.php" "${SIMPLESAMLPHP_CONF_DIR}";
    remoteip_setup_php_trust_forwarded_headers_configure "${SIMPLESAMLPHP_CONF_DIR}/trust-forwarded-headers.php"
}

function remoteip_setup_php_trust_forwarded_headers_configure()
{
    if [[ $# -lt 1 ]]; then
        echo >&2 'Expected config file path';
        return 1;
    fi

    local config_file="$1"

    if [[ ! -z "${APACHE2_REMOTEIP_TRUSTPROXY_HOSTNAME+x}" ]]; then
        __remoteip_set_config  $config_file "trustForwardedHeaders" "true"
    else
        __remoteip_set_config  $config_file "trustForwardedHeaders" "false"
    fi

}

#
# Utils
#

function __remoteip_set_config()
{
    local config_file="$1"
    local key="$2"
    local value="$3"
    sed -i -r -e "/^\s*['\"]$(__sed_escape_lhs "$key")['\"]/s/>(\s*)(.*)/>\1$(__sed_escape_rhs "$value"),/g" "$config_file"
}

#
# Main
#

remoteip_setup_apache2
remoteip_setup_php_trust_forwarded_headers