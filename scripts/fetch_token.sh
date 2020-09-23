#!/bin/sh
set -e
HOST="host"
PORT="8080"
REALM="master"
TOKEN_ENDPOINT="http://$HOST:$PORT/auth/realms/$REALM/protocol/openid-connect/token"
CLIENT_ID="TODO"
CLIENT_SECRET="TODO"
GRANT_TYPE="password"
USERNAME="TODO"
PASSWORD="TODO"
SCOPE=""
RESPONSE_TYPE="token"

command -v jq >/dev/null 2>&1 || { echo >&2 "jq is required to run this script."; exit 1; }
command -v curl >/dev/null 2>&1 || { echo >&2 "curl is required to run this script."; exit 1; }
command -v base64 >/dev/null 2>&1 || { echo >&2 "base64 is required to run this script."; exit 1; }

curl -s \
     -S \
     -d "grant_type=$GRANT_TYPE" \
     -d "client_id=$CLIENT_ID" \
     -d "client_secret=$CLIENT_SECRET" \
     -d "username=$USERNAME" \
     -d "password=$PASSWORD" \
     -d "scope=$SCOPE" \
     -d "response_type=$RESPONSE_TYPE" \
     $TOKEN_ENDPOINT    | \
     jq ".access_token" | \
     cut -d "." -f 2    | \
     base64 -d          | \
     jq
