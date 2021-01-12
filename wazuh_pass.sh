#!/bin/bash

#Run with "sudo elastic_pass.sh <old_password> <new_password>"

TOKEN=$(curl -u wazuh:$1 -k -X GET "https://localhost:55000/security/user/authenticate?raw=true")
JSON='{ "password": "'"$2"'", "allow_run_as": false }'
curl -k -X PUT "https://localhost:55000/security/users/1" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d "$JSON"
