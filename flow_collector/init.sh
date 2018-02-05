#!/usr/bin/env bash

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
/usr/bin/env python /root/data/ipfix.py &
/usr/bin/env python /root/data/netflow_v5.py &
/usr/bin/env python /root/data/netflow_v9.py &
/usr/bin/env python /root/data/sflow.py
