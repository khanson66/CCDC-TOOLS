#!/bin/bash

#Use script with "sudo log_manager.sh <subnet_ip_address>"

#IPTABLES SETUP
systemctl disable firewalld
yum -y install iptables-services
systemctl enable iptables
systemctl start iptables
service iptables save
IPTABLES_RULES=$(cat /etc/sysconfig/iptables-config)
NEW_FILE=$(echo "$IPTABLES_RULES" | sed 's/IPTABLES_SAVE_ON_STOP="no"/IPTABLES_SAVE_ON_STOP="yes"/' | sed 's/IPTABLES_SAVE_ON_RESTART="no"/IPTABLES_SAVE_ON_RESTART="yes"/')
echo "$NEW_FILE" > /etc/sysconfig/iptables-config && echo "iptables setup complete"

#IPTABLES RULES
iptables -F
iptables -A INPUT -s $1/24 -p tcp --dport 1514 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -s $1/24 -p udp --dport 1514 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -s $1/24 -p tcp --dport 1515 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -s $1/24 -p tcp --dport 5601 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -s $1/24 -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -s $1/24 -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -d $1/24 -p tcp --sport 1514 -j ACCEPT
iptables -A OUTPUT -d $1/24 -p udp --sport 1514 -j ACCEPT
iptables -A OUTPUT -d $1/24 -p tcp --sport 1515 -j ACCEPT
iptables -A OUTPUT -d $1/24 -p tcp --sport 5601 -j ACCEPT
iptables -A OUTPUT -d $1/24 -p tcp --sport 443 -j ACCEPT
iptables -A OUTPUT -d $1/24 -p tcp --sport 80 -j ACCEPT
iptables-save
service iptables save && echo "iptables rules set"

#BREAD CRUMBS
CRUMBS="PROMPT_COMMAND='LAST_COMMAND=\$(history 1 | sed 's/-/\\\\-/') && logger -i -p local5.info -t bash \"\$USER \$(tty): \$LAST_COMMAND\"'"
echo "$CRUMBS" >> /etc/bashrc
. /etc/bashrc

#ELASTIC STACK & WAZUH
curl -so ~/all-in-one-installation.sh https://raw.githubusercontent.com/wazuh/wazuh-documentation/4.0/resources/elastic-stack/unattended-installation/all-in-one-installation.sh && bash ~/all-in-one-installation.sh -i
echo "SYSTEM IS UP AND RUNNING"
