#!/bin/bash

if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

mkdir /etc/clarus

cp src/main/resources/clarus-keystore.conf /etc/clarus/
