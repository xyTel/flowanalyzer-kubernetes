#!/usr/bin/env bash

if [ "$1" = "init" ]; then
	if [ -z $BULK_INSERT_COUNT ]
	then
		BULK_INSERT_COUNT=700
	fi

	if [ -z $FLOW_ELASTICSEARCH_SERVICE_HOST ]
	then
		FLOW_ELASTICSEARCH_SERVICE_HOST="localhost"
	fi
	
	cat > /root/data/netflow_options.py << EOF
	bulk_insert_count = $BULK_INSERT_COUNT
	netflow_v5_port = 2055
	netflow_v9_port = 9995
	ipfix_port = 4739
	sflow_port = 6343
	elasticsearch_host = '$FLOW_ELASTICSEARCH_SERVICE_HOST'
	dns = True
	lookup_internal = False
	mac_lookup = True
EOF

elif [ "$1" = "ipfix" ]; then
/usr/bin/env python /root/data/ipfix.py
elif [ "$1" = "netflow_v5" ]; then
/usr/bin/env python /root/data/netflow_v5.py
elif [ "$1" = "netflow_v9" ]; then
/usr/bin/env python /root/data/netflow_v9.py
elif [ "$1" = "sflow" ]; then
/usr/bin/env python /root/data/sflow.py
else 
printf "Usage: %s {init, ipfix, netflow_v5, netflow_v9, sflow}\n" $0
fi
