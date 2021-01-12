#!/bin/bash

#Run with "sudo zeek_json.sh"

/opt/bro/bin/zeekctl stop
INSERT="@load policy/tuning/json-logs.zeek"
echo "$INSERT" >> /opt/bro/share/zeek/site/local.zeek
/opt/bro/bin/zeekctl deploy
