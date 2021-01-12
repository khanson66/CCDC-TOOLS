#!/bin/bash

#Run with "sudo elastic_pass.sh <old_password> <new_password> <elastic_ip_address>"

JSON='{ "password": "'"$2"'" }'
curl -k -X POST -u elastic:$1 "https://$3:9200/_security/user/elastic/_password?pretty" -H 'Content-Type: application/json' -d "$JSON"
