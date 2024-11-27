#!/usr/bin/env bash
set -euo pipefail
[[ "${DEBUG:-false}" == "true" ]] && set -x

SIMPLE_SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
source "${SIMPLE_SCRIPT_DIR}/common.sh"
source "${SIMPLE_SCRIPT_DIR}/env.sh"

if [[ $# -lt 1 ]]; then
    __log "group 'id' expected";
    exit 1;
fi
group_id=$1

RUN_IN_CONTAINER="${KEYCLOAK_IN_CONTAINER}"
RUN_IN_CONTAINER_NAME="${KEYCLOAK_CONTAINER_NAME}"
__keycloak_login
__run_command /opt/keycloak/bin/kcadm.sh get "groups/${group_id}"
