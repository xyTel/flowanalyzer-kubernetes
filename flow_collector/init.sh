#!/usr/bin/env bash

if [ -z $BULK_INSERT_COUNT ]
then
	BULK_INSERT_COUNT=700
fi
	

if [ -z $1 ]
then
	printf "Usage: %s <es_host> <command...>" $0
fi

cat > /root/data/netflow_options.py << EOF
bulk_insert_count = $BULK_INSERT_COUNT
netflow_v5_port = 2055
netflow_v9_port = 9995
ipfix_port = 4739
sflow_port = 6343
elasticsearch_host = '$1'
dns = True
lookup_internal = False
mac_lookup = True
EOF
shift
/usr/bin/env "$@"
