#!/bin/bash

#Run with "sudo ccdc_debian_setup.sh <wazuh_server_ip_address>"

#IPTABLES SETUP
apt-get -y install iptables-services
systemctl disable firewalld
systemctl enable iptables
systemctl start iptables
service iptables save
IPTABLES_CONF=$(cat /etc/sysconfig/iptables-config)
NEW_CONF=$(echo "$IPTABLES_CONF" | sed 's/IPTABLES_SAVE_ON_STOP="no"/IPTABLES_SAVE_ON_STOP="yes"/'\
| sed 's/IPTABLES_SAVE_ON_RESTART="no"/IPTABLES_SAVE_ON_RESTART="yes"/')
echo "$NEW_CONF" > /etc/sysconfig/iptables-config && echo "iptables setup complete"

#BREAD CRUMBS
CRUMBS="PROMPT_COMMAND='LAST_COMMAND=\$(history 1 | sed 's/-/\\\\-/') && logger -i -p local5.info -t bash \"\$USER \$(tty): \$LAST_COMMAND\"'"
echo "$CRUMBS" >> /etc/bash.bashrc
. /etc/bash.bashrc && echo "Bread crumbs are scattered"

#DEPLOY AGENT
curl -so wazuh-agent.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.0.3-1_amd64.deb && sudo WAZUH_MANAGER='$1' dpkg -i ./wazuh-agent.deb
systemctl start wazuh-agent && echo "Agent Deployed"

echo "LET'S GO BOOIIIZZZZ!!!!!"
