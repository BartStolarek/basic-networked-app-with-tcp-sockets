#!/bin/bash

if [ $# -ne 2 ]; then
    echo "Usage: $0 <hostname> <port>"
    exit 1
fi

hostname=$1
port=$2

python client.py "$hostname" "$port"