#!/usr/bin/env bash

if [ -z $1 ]
then
	printf "Usage: %s <es_host> <command...>" $0
fi

cat > netflow_options.py << EOF
bulk_insert_count = 700
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
