#!/usr/bin/env bash

# see http://stackoverflow.com/a/2705678/433558
function __sed_escape_lhs()
{
    echo "$@" | sed -e 's/[]\/$*.^|[]/\\&/g'
}

function __sed_escape_rhs()
{
    echo "$@" | sed -e 's/[\/&]/\\&/g'
}


# function __php_escape()
# {
#     php -r 'var_export(('$2') $argv[1]);' -- "$1"
# }

function __php_escape()
{
    local value="$1"
    local var_type="$2"
    local escaped="$(php -r 'var_export(('"$var_type"') $argv[1]);' -- "$value")"
    if [ "$var_type" = 'string' ] && [ "${escaped:0:1}" = "'" ]; then
        escaped="${escaped//$'\n'/"' + \"\\n\" + '"}"
    fi
    echo "$escaped"
}

true