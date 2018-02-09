#!/usr/bin/env bash

envsubst < /root/data/netflow_options.template > /root/data/netflow_options.py

if [ "$1" = "ipfix" ]; then
/usr/bin/env python /root/data/ipfix.py
elif [ "$1" = "netflow_v5" ]; then
/usr/bin/env python /root/data/netflow_v5.py
elif [ "$1" = "netflow_v9" ]; then
/usr/bin/env python /root/data/netflow_v9.py
elif [ "$1" = "sflow" ]; then
/usr/bin/env python /root/data/sflow.py
else 
printf "Usage: %s {ipfix, netflow_v5, netflow_v9, sflow}\n" $0
fi
