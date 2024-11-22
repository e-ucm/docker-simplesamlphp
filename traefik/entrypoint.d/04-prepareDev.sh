#!/usr/bin/env sh
set -euo pipefail
[[ "${DEBUG:-false}" == "true" ]] && set -x

: ${SIMVA_EXTENSIONS_VERSION:="1.0.0"}
: ${JQ_VERSION:="1.7.1"}
: ${EXTERNAL_DOMAIN:="external.test"}
: ${INTERNAL_DOMAIN:="internal.test"}
: ${SIMVA_EXTENSIONS:="es.e-ucm.simva.keycloak.fullname-attribute-mapper es.e-ucm.simva.keycloak.policy-attribute-mapper"}

old_cwd=$PWD

cd /simva

if [[ ! -d "ext" ]]; then
    mkdir ext;
fi

cd ext
for ext in $SIMVA_EXTENSIONS; do
    ext_jar="${ext}-${SIMVA_EXTENSIONS_VERSION}.jar"
    if [[ ! -f "${ext_jar}" ]]; then
        wget -q "https://github.com/e-ucm/keycloak-extensions/releases/download/v${SIMVA_EXTENSIONS_VERSION}/${ext_jar}"
        shasums="SHA256SUMS-${SIMVA_EXTENSIONS_VERSION}"
        if [[ ! -f "${shasums}" ]]; then
            wget -q -O "${shasums}" "https://github.com/e-ucm/keycloak-extensions/releases/download/v${SIMVA_EXTENSIONS_VERSION}/SHA256SUMS"
        fi
        echo "$(cat "${shasums}"  | grep "${ext_jar}" | cut -d' ' -f1) ${ext_jar}" | sha256sum -c -w -s -
    fi
done
cd ..

if [[ ! -f "jq" ]]; then
    wget -q -O jq "https://github.com/jqlang/jq/releases/download/jq-${JQ_VERSION}/jq-linux-amd64"
    chmod +x jq
fi

cd $old_cwd > /dev/null 2>&1
