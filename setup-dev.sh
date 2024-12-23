#!/usr/bin/env bash
set -euo pipefail
[[ "${DEBUG:-false}" == "true" ]] && set -x

SIMPLE_SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
source "${SIMPLE_SCRIPT_DIR}/keycloak/common.sh"
source "${SIMPLE_SCRIPT_DIR}/keycloak/env.sh"

for d in ./data/{apache2,keycloak/mariadb,keycloak/providers,simplesamlphp,simva,traefik}; do
    if [[ ! -d "$d" ]]; then
        mkdir -p "$d"
    fi
done

# Launch this container to generate al required config / dependencies
docker compose up traefik -d
"${SIMPLE_SCRIPT_DIR}/overlay/usr/local/bin/wait-for" -t 60 localhost:80 -- sleep 10 && echo "dev setup finished and traefik running"

# Launch the rest of the containers
docker compose up -d

set +e
sso_ip=$(getent hosts "${KEYCLOAK_SERVER_HOST}")
result=$?
set -e

if [[ "$result" -ne 0 ]]; then
    __log "Can't resolve ""${KEYCLOAK_SERVER_HOST}"", check README.md and run the script again"
    exit
fi

export KEYCLOAK_IN_CONTAINER=true
"${SIMPLE_SCRIPT_DIR}/keycloak/config-saml-client.sh"
