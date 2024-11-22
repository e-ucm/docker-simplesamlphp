#!/usr/bin/env bash

declare -x APACHE2_REMOTEIP_TRUSTPROXY_IP
[[ -z "${APACHE2_REMOTEIP_TRUSTPROXY_IP}" ]] && APACHE2_REMOTEIP_TRUSTPROXY_IP=""

declare -x APACHE2_REMOTEIP_TRUSTPROXY_HOSTNAME
[[ -z "${APACHE2_REMOTEIP_TRUSTPROXY_HOSTNAME}" ]] && APACHE2_REMOTEIP_TRUSTPROXY_HOSTNAME=""

true