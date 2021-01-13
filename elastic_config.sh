#!/bin/bash

#Run with "sudo elastic_config.sh"

#CONFIGURATION
FILEBEAT_CONF=$(cat /etc/filebeat/filebeat.yml)
NEW_FILEBEAT=$(echo "$FILEBEAT_CONF" | sed 's/ enabled: false/ enabled: true/')
echo "$NEW_FILEBEAT" > /etc/filebeat/filebeat.yml

OSSEC_CONF=$(cat /var/ossec/etc/ossec.conf)
NEW_OSSEC=$(echo "$OSSEC_CONF" | sed 's/<logall>no<\/logall>/<logall>yes<\/logall>/'\
| sed 's/<logall_json>no<\/logall_json>/<logall_json>yes<\/logall_json>/'\
| sed 's/<frequency>43200<\/frequency>/<frequency>60<\/frequency>/')
echo "$NEW_OSSEC" > /var/ossec/etc/ossec.conf

#RESTART SERVICES
systemctl enable elasticsearch
systemctl enable filebeat
systemctl enable kibana
systemctl enable wazuh-manager
systemctl restart elasticsearch
systemctl restart filebeat
systemctl restart kibana
systemctl restart wazuh-manager

#SEARCHES
SEARCHES=$(printf "Successful User Logon\n\"session opened\" OR \"accepted password\" OR \"accepted publickey\" OR data.win.system.eventID:4624\n"\
"Failed User Logon\n\"authentication failure\" OR \"failed password\" OR data.win.system.eventID: 4625\n"\
"User Logoff\n\"session closed\" OR data.win.system.eventID: 4634\n"\
"Sudo / Privlaged Actions\n\"sudo\" OR \"FAILED su\"\n"\
"Log Tampering\ndata.win.system.eventID:4719 OR data.win.system.eventID:1102 OR \"bashrc\"\n"\
"Service Installation\ndata.win.system.eventID:4697 OR \"apt-get\" OR \"apt install\" OR \"wget\" OR \"yum install\"\n"\
"User Modification\n\"usermod\" OR \"useradd\" OR \"adduser\" OR data.win.system.eventID:4720 OR data.win.system.eventID:4722 OR "\
"data.win.system.eventID:4725 OR data.win.system.eventID:4738 OR data.win.system.eventID:4740 OR data.win.system.eventID:4767\n"\
"Group Modification\n\"groupadd\" OR \"groupmod\" OR \"addgroup\" OR data.win.system.eventID:4735 OR data.win.system.eventID:4737 OR data.win.system.eventID:4755\n"\
"Zeek/Bro Logs\nlocation: /opt/bro/spool/manager/*.log\n"\
"Bash Command Stream: full_log, agent.name, agent.id, predecoder.timestamp\n(location:/var/log/messages OR location:/var/log/syslog) AND \"bash\"\n"\
"Powershell Command Stream: data.win.eventdata.scriptBlockText, agent.id, agent.name, data.win.system.process, @timestamp\ndata.win.system.eventID:4104")
echo "$SEARCHES" > ~/searches.txt

#AGENT.CONF
AGENT=$( printf "<agent_config os=\"Linux\">\n"\
"  <syscheck>\n"\
"    <disabled>no</disabled>\n"\
"    <frequency>60</frequency>\n"\
"    <scan_on_start>yes</scan_on_start>\n"\
"    <!-- Generate alert when new file detected -->\n"\
"    <alert_new_files>yes</alert_new_files>\n"\
"    <!-- Don't ignore files that change more than 'frequency' times -->\n"\
"    <auto_ignore frequency=\"10\" timeframe=\"3600\">no</auto_ignore>\n"\
"    <!-- Directories to check  (perform all possible verifications) -->\n"\
"    <directories>/etc,/usr/bin,/usr/sbin</directories>\n"\
"    <directories>/bin,/sbin,/boot</directories>\n"\
"    <!-- Files/directories to ignore -->\n"\
"    <ignore>/etc/mtab</ignore>\n"\
"    <ignore>/etc/hosts.deny</ignore>\n"\
"    <ignore>/etc/mail/statistics</ignore>\n"\
"    <ignore>/etc/random-seed</ignore>\n"\
"    <ignore>/etc/random.seed</ignore>\n"\
"    <ignore>/etc/adjtime</ignore>\n"\
"    <ignore>/etc/httpd/logs</ignore>\n"\
"    <ignore>/etc/utmpx</ignore>\n"\
"    <ignore>/etc/wtmpx</ignore>\n"\
"    <ignore>/etc/cups/certs</ignore>\n"\
"    <ignore>/etc/dumpdates</ignore>\n"\
"    <ignore>/etc/svc/volatile</ignore>\n"\
"    <!-- File types to ignore -->\n"\
"    <ignore type=\"sregex\">.log$|.swp$</ignore>\n"\
"    <!-- Check the file, but never compute the diff -->\n"\
"    <nodiff>/etc/ssl/private.key</nodiff>\n"\
"    <skip_nfs>yes</skip_nfs>\n"\
"    <skip_dev>yes</skip_dev>\n"\
"    <skip_proc>yes</skip_proc>\n"\
"    <skip_sys>yes</skip_sys>\n"\
"    <!-- Nice value for Syscheck process -->\n"\
"    <process_priority>10</process_priority>\n"\
"    <!-- Maximum output throughput -->\n"\
"    <max_eps>100</max_eps>\n"\
"    <!-- Database synchronization settings -->\n"\
"    <synchronization>\n"\
"      <enabled>yes</enabled>\n"\
"      <interval>5m</interval>\n"\
"      <max_interval>1h</max_interval>\n"\
"      <max_eps>10</max_eps>\n"\
"    </synchronization>\n"\
"  </syscheck>\n"\
"  <active-response>\n"\
"    <disabled>no</disabled>\n"\
"    <command>firewall-drop</command>\n"\
"    <location>all</location>\n"\
"    <level>10</level>\n"\
"    <timeout>1800</timeout>\m"\
"  </active-response>\n"\
"  <active-response>\n"\
"    <disabled>no</disabled>\n"\
"    <command>host-deny</command>\n"\
"    <location>all</location>\n"\
"    <level>10</level>\n"\
"    <timeout>1800</timeout>\n"\
"  </active-response>\n"\
"</agent_config>\n"\
"\n"\
"<agent_config profile=\"ubuntu\">\n"\
"  <localfile>\n"\
"    <log_format>syslog</log_format>\n"\
"    <location>/var/log/auth.log</location>\n"\
"  </localfile>\n"\
"  <localfile>\n"\
"    <log_format>syslog</log_format>\n"\
"    <location>/var/log/syslog</location>\n"\
"  </localfile>\n"\
"  <localfile>\n"\
"    <log_format>syslog</log_format>\n"\
"    <location>/opt/bro/spool/manager/*.log</location>\n"\
"  </localfile>\n"\
"</agent_config>\n"\
"\n"\
"<agent_config os=\"Windows\">\n"\
"  <localfile>\n"\
"    <location>Windows Powershell</location>\n"\
"    <log_format>eventchannel</log_format>\n"\
"  </localfile>\n"\
"  <localfile>\n"\
"    <location>Microsoft-Windows-Powershell/Operational</location>\n"\
"    <log_format>eventchannel</log_format>\n"\
"  </localfile>\n"\
"  <active-response>\n"\
"    <disabled>no</disabled>\n"\
"    <command>route-null</command>\n"\
"    <location>all</location>\n"\
"    <level>10</level>\n"\
"    <timeout>1800</timeout>\n"\
"  </active-response>\n"\
"  <active-response>\n"\
"    <disabled>no</disabled>\n"\
"    <command>netsh</command>\n"\
"    <location>all</location>\n"\
"    <level>10</level>\n"\
"    <timeout>1800</timeout>\n"\
"  </active-response>\n"\
"  <syscheck>\n"\
"    <disabled>no</disabled>\n"\
"    <frequency>60</frequency>\n"\
"    <!-- Default files to be monitored. -->\n"\
"    <directories recursion_level=\"0\" restrict=\"regedit.exe$|system.ini$|win.ini$\">%%WINDIR%%</directories>\n"\
"    <directories recursion_level=\"0\" restrict=\"at.exe$|attrib.exe$|cacls.exe$|cmd.exe$|eventcreate.exe$|ftp.exe$|lsass.exe$|net.exe$|net1.exe$|netsh.exe$|reg.exe$|regedt32.exe|regsvr32.exe|runas.exe|sc.exe|schtasks.exe|sethc.exe|subst.exe$\">%%WINDIR%%\\SysNative</directories>\n"\
"    <directories recursion_level=\"0\">%%WINDIR%%\\SysNative\\drivers\\\etc</directories>\n"\
"    <directories recursion_level=\"0\" restrict=\"WMIC.exe$\">%%WINDIR%%\\SysNative\\wbem</directories>\n"\
"    <directories recursion_level=\"0\" restrict=\"powershell.exe$\">%%WINDIR%%\\SysNative\\WindowsPowerShell\\\v1.0</directories>\n"\
"    <directories recursion_level=\"0\" restrict=\"winrm.vbs$\">%%WINDIR%%\\SysNative</directories>\n"\
"    <!-- 32-bit programs. -->\n"\
"    <directories recursion_level=\"0\" restrict=\"at.exe$|attrib.exe$|cacls.exe$|cmd.exe$|eventcreate.exe$|ftp.exe$|lsass.exe$|net.exe$|net1.exe$|netsh.exe$|reg.exe$|regedit.exe$|regedt32.exe$|regsvr32.exe$|runas.exe$|sc.exe$|schtasks.exe$|sethc.exe$|subst.exe$\">%%WINDIR%%\\System32</directories>\n"\
"    <directories recursion_level=\"0\">%%WINDIR%%\\System32\\drivers\\\etc</directories>\n"\
"    <directories recursion_level=\"0\" restrict=\"WMIC.exe$\">%%WINDIR%%\\System32\\wbem</directories>\n"\
"    <directories recursion_level=\"0\" restrict=\"powershell.exe$\">%%WINDIR%%\\System32\\WindowsPowerShell\\\v1.0</directories>\n"\
"    <directories recursion_level=\"0\" restrict=\"winrm.vbs$\">%%WINDIR%%\\System32</directories>\n"\
"    <directories realtime=\"yes\">%%PROGRAMDATA%%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup</directories>\n"\
"    <ignore>%%PROGRAMDATA%%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\desktop.ini</ignore>\n"\
"    <ignore type=\"sregex\">.log$|.htm$|.jpg$|.png$|.chm$|.pnf$|.evtx$</ignore>\n"\
"    <!-- Windows registry entries to monitor. -->\n"\
"    <windows_registry>HKEY_LOCAL_MACHINE\\Software\\Classes\\\batfile</windows_registry>\n"\
"    <windows_registry>HKEY_LOCAL_MACHINE\\Software\\Classes\\cmdfile</windows_registry>\n"\
"    <windows_registry>HKEY_LOCAL_MACHINE\\Software\\Classes\\comfile</windows_registry>\n"\
"    <windows_registry>HKEY_LOCAL_MACHINE\\Software\\Classes\\\exefile</windows_registry>\n"\
"    <windows_registry>HKEY_LOCAL_MACHINE\\Software\\Classes\\piffile</windows_registry>\n"\
"    <windows_registry>HKEY_LOCAL_MACHINE\\Software\\Classes\\AllFilesystemObjects</windows_registry>\n"\
"    <windows_registry>HKEY_LOCAL_MACHINE\\Software\\Classes\\Directory</windows_registry>\n"\
"    <windows_registry>HKEY_LOCAL_MACHINE\\Software\\Classes\\Folder</windows_registry>\n"\
"    <windows_registry arch=\"both\">HKEY_LOCAL_MACHINE\\Software\\Classes\\Protocols</windows_registry>\n"\
"    <windows_registry arch=\"both\">HKEY_LOCAL_MACHINE\\Software\\Policies</windows_registry>\n"\
"    <windows_registry>HKEY_LOCAL_MACHINE\\Security</windows_registry>\n"\
"    <windows_registry arch=\"both\">HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Internet Explorer</windows_registry>\n"\
"    <windows_registry>HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services</windows_registry>\n"\
"    <windows_registry>HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs</windows_registry>\n"\
"    <windows_registry>HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\SecurePipeServers\\winreg</windows_registry>\n"\
"    <windows_registry arch=\"both\">HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run</windows_registry>\n"\
"    <windows_registry arch=\"both\">HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce</windows_registry>\n"\
"    <windows_registry>HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx</windows_registry>\n"\
"    <windows_registry arch=\"both\">HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\\URL</windows_registry>\n"\
"    <windows_registry arch=\"both\">HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies</windows_registry>\n"\
"    <windows_registry arch=\"both\">HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows</windows_registry>\n"\
"    <windows_registry arch=\"both\">HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon</windows_registry>\n"\
"    <windows_registry arch=\"both\">HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Active Setup\\Installed Components</windows_registry>\n"\
"    <!-- Windows registry entries to ignore. -->\n"\
"    <registry_ignore>HKEY_LOCAL_MACHINE\\Security\\Policy\\Secrets</registry_ignore>\n"\
"    <registry_ignore>HKEY_LOCAL_MACHINE\\Security\\SAM\\Domains\\Account\\\Users</registry_ignore>\n"\
"    <registry_ignore type=\"sregex\">\\\Enum$</registry_ignore>\n"\
"    <registry_ignore>HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\MpsSvc\\Parameters\\AppCs</registry_ignore>\n"\
"    <registry_ignore>HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\MpsSvc\\Parameters\\PortKeywords\\DHCP</registry_ignore>\n"\
"    <registry_ignore>HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\MpsSvc\\Parameters\\PortKeywords\\IPTLSIn</registry_ignore>\n"\
"    <registry_ignore>HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\MpsSvc\\Parameters\\PortKeywords\\IPTLSOut</registry_ignore>\n"\
"    <registry_ignore>HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\MpsSvc\\Parameters\\PortKeywords\\RPC-EPMap</registry_ignore>\n"\
"    <registry_ignore>HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\MpsSvc\\Parameters\\PortKeywords\\Teredo</registry_ignore>\n"\
"    <registry_ignore>HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\PolicyAgent\\Parameters\\Cache</registry_ignore>\n"\
"    <registry_ignore>HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx</registry_ignore>\n"\
"    <registry_ignore>HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\ADOVMPPackage\\Final</registry_ignore>\n"\
"    <!-- Frequency for ACL checking (seconds) -->\n"\
"    <windows_audit_interval>60</windows_audit_interval>\n"\
"    <!-- Nice value for Syscheck module -->\n"\
"    <process_priority>10</process_priority>\n"\
"    <!-- Maximum output throughput -->\n"\
"    <max_eps>100</max_eps>\n"\
"    <!-- Database synchronization settings -->\n"\
"    <synchronization>\n"\
"      <enabled>yes</enabled>\n"\
"      <interval>5m</interval>\n"\
"      <max_interval>1h</max_interval>\n"\
"      <max_eps>10</max_eps>\n"\
"    </synchronization>\n"\
"  </syscheck>\n"\
"</agent_config>")
echo "$AGENT" > ~/agent.conf
