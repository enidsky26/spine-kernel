#!/bin/bash

module=${1:-"neo"}

if [ "$EUID" -ne 0 ]; then 
    echo "error: must run as root"
    usage
    exit 1
fi

# invoke rmmod with all arguments we got
# /sbin/rmmod $module $* || exit 1
/sbin/rmmod $module || exit 1
