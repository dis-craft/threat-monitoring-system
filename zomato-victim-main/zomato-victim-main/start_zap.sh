#!/bin/bash
# Replace this path with your actual ZAP installation path
ZAP_PATH="/usr/local/bin/zap.sh"
ZAP_API_KEY="zap123"

echo "Starting ZAP in daemon mode with API key: $ZAP_API_KEY"
echo "(This terminal must remain open while using the vulnerability scanner)"

# Export the API key for the Python app
export ZAP_API_KEY="$ZAP_API_KEY"

# Start ZAP in daemon mode with the API key
$ZAP_PATH -daemon -host 127.0.0.1 -port 8080 -config api.key=$ZAP_API_KEY -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true 