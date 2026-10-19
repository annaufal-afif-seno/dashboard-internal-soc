# LAPORAN EKSPOR ALERT WAZUH DARI VM (OFFLINE READABLE)

- **Waktu Ekspor:** 2026-10-16 17:25:14 WIB
- **Sumber Data:** VM Dashboard `192.168.30.206` (PostgreSQL `wazuh_soc_db`)
- **Total Raw Alert:** 1,939 events
- **Total Tiket Insiden:** 117 tickets

## 1. Distribusi Alert per Tenant

| Tenant ID | Jumlah Raw Alert |
| :--- | :---: |
| **DEFAULT** | 1,018 |
| **TenantC** | 416 |
| **TenantD** | 380 |
| **TenantA** | 122 |
| **TenantB** | 3 |

## 2. Distribusi Alert per Agent / Host

| Host / Agent Name | Agent ID | Tenant | Jumlah Alert |
| :--- | :---: | :---: | :---: |
| `isif-rproxy-155` | `035` | TenantD | 378 |
| `dashboard-multitenant-asoc-103` | `042` | DEFAULT | 368 |
| `hportal-prod-159` | `019` | TenantC | 339 |
| `soc-internal-dashboard-86` | `041` | DEFAULT | 331 |
| `multitenant-soc-131` | `000` | DEFAULT | 220 |
| `n8n-misp-134` | `038` | TenantA | 94 |
| `portal-asoc-219` | `040` | DEFAULT | 85 |
| `Learning-acadcsirt-dimas-123` | `021` | TenantC | 63 |
| `zabbix-prod-214` | `012` | TenantA | 20 |
| `leaning-sgu-dimas-124` | `023` | TenantC | 13 |
| `wazuh.manager` | `000` | DEFAULT | 11 |
| `Grafana-143` | `036` | TenantA | 3 |
| `mongodb-ext-158` | `003` | TenantA | 2 |
| `discourse-180` | `006` | TenantA | 2 |
| `elastic-prod-239` | `015` | TenantB | 2 |
| `None` | `000` | DEFAULT | 1 |
| `web-ecommerce-prod` | `005` | DEFAULT | 1 |
| `server-dmz-test` | `001` | DEFAULT | 1 |
| `hp-fluentd-tenant-172` | `005` | TenantA | 1 |
| `mongo-replica3-199` | `032` | TenantD | 1 |
| `rocky10-terminal-196` | `025` | TenantD | 1 |
| `automation-parallel-243` | `018` | TenantC | 1 |
| `mongodb-honeypot-230` | `013` | TenantB | 1 |

## 3. Top Aturan / Rule Wazuh yang Terdeteksi

| Rule ID | Level | Deskripsi Rule | Jumlah Event |
| :---: | :---: | :--- | :---: |
| `31301` | 3 | Nginx error message. | 370 |
| `31101` | 5 | Web server 400 error code. | 315 |
| `5502` | 3 | PAM: Login session closed. | 113 |
| `5501` | 3 | PAM: Login session opened. | 111 |
| `2904` | 7 | Dpkg (Debian Package) half configured. | 110 |
| `5402` | 3 | Successful sudo to ROOT executed. | 70 |
| `2902` | 7 | New dpkg (Debian Package) installed. | 66 |
| `5715` | 3 | sshd: authentication success. | 38 |
| `40704` | 5 | Systemd: Service exited due to a failure. | 22 |
| `31151` | 10 | Multiple web server 400 error codes from same source ip. | 22 |
| `31410` | 3 | PHP Warning message. | 21 |
| `31533` | 10 | High amount of POST requests in a small period of time (likely bot). | 18 |
| `86003` | 3 | Docker: Error message | 12 |
| `5503` | 5 | PAM: User login failed. | 9 |
| `533` | 7 | Listened ports status (netstat) changed (new port opened or closed). | 8 |
| `5710` | 5 | sshd: Attempt to login using a non-existent user | 7 |
| `591` | 3 | Log file rotated. | 6 |
| `31516` | 6 | Suspicious URL access. | 5 |
| `5760` | 5 | sshd: authentication failed. | 4 |
| `19003` | 5 | SCA summary: CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Score less than 80% (50) | 3 |
| `0` | - | Raw Stream Ingested Event | 2 |
| `19009` | 3 | CIS Benchmark for Amazon Linux 2023 Benchmark v1.0.0.: Ensure sudo is installed. | 2 |
| `19009` | 3 | CIS Benchmark for Amazon Linux 2023 Benchmark v1.0.0.: Ensure sticky bit is set on all world-writable directories. | 2 |
| `506` | 3 | Wazuh agent stopped. | 2 |
| `503` | 3 | Wazuh agent started. | 2 |
| `501` | 3 | New wazuh agent connected. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure mounting of cramfs filesystems is disabled. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure freevxfs kernel module is not available. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure hfs kernel module is not available. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure hfsplus kernel module is not available. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure jffs2 kernel module is not available. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure overlayfs kernel module is not available. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure squashfs kernel module is not available. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure udf kernel module is not available. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure usb-storage kernel module is not available. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure unused filesystems kernel modules are not available. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure /tmp is a separate partition. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure nodev option set on /tmp partition. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure nosuid option set on /tmp partition. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure noexec option set on /tmp partition. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure /dev/shm is a separate partition. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure nodev option set on /dev/shm partition. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure nosuid option set on /dev/shm partition. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure noexec option set on /dev/shm partition. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure separate partition exists for /home. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure nodev option set on /home partition. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure nosuid option set on /home partition. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure separate partition exists for /var. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure nodev option set on /var partition. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure nosuid option set on /var partition. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure separate partition exists for /var/tmp. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure nodev option set on /var/tmp partition. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure nosuid option set on /var/tmp partition. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure noexec option set on /var/tmp partition. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure separate partition exists for /var/log. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure nodev option set on /var/log partition. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure nosuid option set on /var/log partition. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure noexec option set on /var/log partition. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure separate partition exists for /var/log/audit. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure nodev option set on /var/log/audit partition. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure nosuid option set on /var/log/audit partition. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure noexec option set on /var/log/audit partition. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure AppArmor is enabled in the bootloader configuration. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure AppArmor is installed. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure all AppArmor Profiles are in enforce or complain mode. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure all AppArmor Profiles are enforcing. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure access to bootloader config is configured. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure bootloader password is set. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure address space layout randomization is enabled. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure core dumps are restricted. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure prelink is not installed. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure Automatic Error Reporting is not enabled. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure message of the day is configured properly. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure local login warning banner is configured properly. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure remote login warning banner is configured properly. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure access to /etc/motd is configured. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure access to /etc/issue is configured. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure access to /etc/issue.net is configured. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure GDM is removed. | 2 |
| `19009` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure GDM login banner is configured. | 2 |
| `19009` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure GDM disable-user-list option is enabled. | 2 |
| `19009` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure GDM screen locks cannot be overridden. | 2 |
| `19009` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure GDM disabling automatic mounting of removable media is not overridden. | 2 |
| `19009` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure GDM automatic mounting of removable media is disabled. | 2 |
| `19009` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure GDM autorun-never is enabled. | 2 |
| `19009` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure GDM autorun-never is not overridden. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure XDMCP is not enabled. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure autofs services are not in use. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure avahi daemon services are not in use. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure dhcp server services are not in use. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure dns server services are not in use. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure dnsmasq services are not in use. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure ftp server services are not in use. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure ldap server services are not in use. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure message access server services are not in use. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure network file system services are not in use. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure nis server services are not in use. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure print server services are not in use. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure rpcbind services are not in use. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure rsync services are not in use. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure samba file server services are not in use. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure snmp services are not in use. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure tftp server services are not in use. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure web proxy server services are not in use. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure web server services are not in use. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure xinetd services are not in use. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure X window server services are not in use. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure mail transfer agent is configured for local-only mode. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure NIS Client is not installed. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure rsh client is not installed. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure talk client is not installed. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure telnet client is not installed. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure ldap client is not installed. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure ftp client is not installed. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure systemd-timesyncd configured with authorized timeserver. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure systemd-timesyncd is enabled and running. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure chrony is configured with authorized timeserver. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure chrony is running as user _chrony. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure chrony is enabled and running. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure cron daemon is enabled and active. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure permissions on /etc/crontab are configured. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure permissions on /etc/cron.hourly are configured. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure permissions on /etc/cron.daily are configured. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure permissions on /etc/cron.monthly are configured. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure permissions on /etc/cron.weekly are configured. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure permissions on /etc/cron.d are configured. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure crontab is restricted to authorized users. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure at is restricted to authorized users. | 2 |
| `19009` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure wireless interfaces are disabled. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure bluetooth services are not in use. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure dccp kernel module is not available. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure tipc kernel module is not available. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure rds kernel module is not available. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure sctp kernel module is not available. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure ip forwarding is disabled. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure packet redirect sending is disabled. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure bogus icmp responses are ignored. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure broadcast icmp requests are ignored. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure icmp redirects are not accepted. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure secure icmp redirects are not accepted. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure reverse path filtering is enabled. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure source routed packets are not accepted. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure suspicious packets are logged. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure tcp syn cookies is enabled. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure a single firewall configuration utility is in use. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure ipv6 router advertisements are not accepted. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure ufw is installed. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure iptables-persistent is not installed with ufw. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure ufw service is enabled. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure ufw loopback traffic is configured. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure ufw default deny firewall policy. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure nftables is installed. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure ufw is uninstalled or disabled with nftables. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure iptables are flushed with nftables. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure a nftables table exists. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure nftables base chains exist. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure nftables default deny firewall policy. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure nftables service is enabled. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure nftables rules are permanent. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure iptables packages are installed. | 2 |
| `5403` | 4 | First time user executed sudo. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure nftables is not in use with iptables. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure ufw is not in use with iptables. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure iptables loopback traffic is configured. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure iptables default deny firewall policy. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure ip6tables default deny firewall policy. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure ip6tables loopback traffic is configured. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure permissions on SSH private host key files are configured. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure permissions on /etc/ssh/sshd_config are configured. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure permissions on SSH public host key files are configured. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure sshd Banner is configured. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure sshd access is configured. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure sshd Ciphers are configured. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure sshd DisableForwarding is enabled. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure sshd GSSAPIAuthentication is disabled. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure sshd HostbasedAuthentication is disabled. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure sshd IgnoreRhosts is enabled. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure sshd KexAlgorithms is configured. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure sshd LoginGraceTime is configured. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure sshd LogLevel is configured. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure sshd MACs are configured. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure sshd MaxSessions is configured. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure sshd MaxAuthTries is configured. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure sshd MaxStartups is configured. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure sshd PermitEmptyPasswords is disabled. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure sshd PermitUserEnvironment is disabled. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure sshd PermitRootLogin is disabled. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure sshd UsePAM is enabled. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure sudo is installed. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure sudo commands use pty. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure sudo log file exists. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure re-authentication for privilege escalation is not disabled globally. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure users must provide password for privilege escalation. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure sudo authentication timeout is configured correctly. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure access to the su command is restricted. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure latest version of pam is installed. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure libpam-modules is installed. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure libpam-pwquality is installed. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure pam_unix module is enabled. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure pam_pwquality module is enabled. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure pam_faillock module is enabled. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure pam_pwhistory module is enabled. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure password unlock time is configured. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure password failed attempts lockout is configured. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure password failed attempts lockout includes root account. | 2 |
| `19009` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure password number of changed characters is configured. | 2 |
| `19009` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure minimum password length is configured. | 2 |
| `19009` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure password complexity is configured. | 2 |
| `19009` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure password same consecutive characters is configured. | 2 |
| `19009` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure password maximum sequential characters is configured. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure password quality checking is enforced. | 2 |
| `19009` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure password dictionary check is enabled. | 2 |
| `19009` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure password quality is enforced for the root user. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure password history remember is configured. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure password history is enforced for the root user. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure pam_unix does not include nullok. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure pam_pwhistory includes use_authtok. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure pam_unix includes a strong password hashing algorithm. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure pam_unix does not include remember. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure password expiration is configured. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure pam_unix includes use_authtok. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure minimum password days is configured. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure password expiration warning days is configured. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure strong password hashing algorithm is configured. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure inactive password lock is configured. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure root is the only UID 0 account. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure root is the only GID 0 account. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure group root is the only GID 0 group. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure root account access is controlled. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure root user umask is configured. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure nologin is not listed in /etc/shells. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure default user shell timeout is configured. | 2 |
| `19009` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure default user umask is configured. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure journald service is enabled and active. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure systemd-journal-remote is installed. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure journald log file rotation is configured. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure systemd-journal-upload is enabled and active. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure systemd-journal-upload authentication is configured. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure systemd-journal-remote service is not in use. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure journald ForwardToSyslog is disabled. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure journald Storage is configured. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure journald Compress is configured. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure rsyslog service is enabled and active. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure rsyslog is installed. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure journald is configured to send logs to rsyslog. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure rsyslog log file creation mode is configured. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure rsyslog is configured to send logs to a remote log host. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure rsyslog is not configured to receive logs from a remote client. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure access to all logfiles has been configured. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure auditd service is enabled and active. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure auditd packages are installed. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure auditing for processes that start prior to auditd is enabled. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure audit_backlog_limit is sufficient. | 2 |
| `19009` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure audit log storage size is configured. | 2 |
| `19009` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure audit logs are not automatically deleted. | 2 |
| `19009` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure system is disabled when audit logs are full. | 2 |
| `19009` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure changes to system administration scope (sudoers) is collected. | 2 |
| `19009` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure system warns when audit logs are low on space. | 2 |
| `19009` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure events that modify the sudo log file are collected. | 2 |
| `19009` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure actions as another user are always logged. | 2 |
| `19009` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure events that modify date and time information are collected. | 2 |
| `19009` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure events that modify the system's network environment are collected. | 2 |
| `19009` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure unsuccessful file access attempts are collected. | 2 |
| `19009` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure events that modify user/group information are collected. | 2 |
| `19009` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure discretionary access control permission modification events are collected. | 2 |
| `19009` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure successful file system mounts are collected. | 2 |
| `19009` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure session initiation information is collected. | 2 |
| `19009` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure login and logout events are collected. | 2 |
| `19009` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure file deletion events by users are collected. | 2 |
| `19009` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure events that modify the system's Mandatory Access Controls are collected. | 2 |
| `19009` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure successful and unsuccessful attempts to use the chcon command are collected. | 2 |
| `19009` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure successful and unsuccessful attempts to use the setfacl command are collected. | 2 |
| `19009` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure successful and unsuccessful attempts to use the chacl command are collected. | 2 |
| `19009` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure successful and unsuccessful attempts to use the usermod command are collected. | 2 |
| `19009` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure kernel module loading unloading and modification is collected. | 2 |
| `19009` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure the running and on disk configuration is the same. | 2 |
| `19009` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure the audit configuration is immutable. | 2 |
| `19009` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure audit log files group owner is configured. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure audit configuration files mode is configured. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure audit configuration files owner is configured. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure audit configuration files group owner is configured. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure audit tools mode is configured. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure audit tools owner is configured. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure audit tools group owner is configured. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure AIDE is installed. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure filesystem integrity is regularly checked. | 2 |
| `19009` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure cryptographic mechanisms are used to protect the integrity of audit tools. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure permissions on /etc/passwd- are configured. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure permissions on /etc/passwd are configured. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure permissions on /etc/group are configured. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure permissions on /etc/group- are configured. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure permissions on /etc/shadow are configured. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure permissions on /etc/shadow- are configured. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure permissions on /etc/gshadow are configured. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure permissions on /etc/gshadow- are configured. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure permissions on /etc/shells are configured. | 2 |
| `19007` | 7 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure permissions on /etc/security/opasswd are configured. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure accounts in /etc/passwd use shadowed passwords. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure /etc/shadow password fields are not empty. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure all groups in /etc/passwd exist in /etc/group. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure shadow group is empty. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure no duplicate UIDs exist. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure no duplicate GIDs exist. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure no duplicate user names exist. | 2 |
| `19008` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure no duplicate group names exist. | 2 |
| `510` | 7 | Host-based anomaly detection event (rootcheck). | 2 |
| `19012` | 5 | CIS Benchmark for Amazon Linux 2023 Benchmark v1.0.0.: Ensure sudo is installed.: Status changed from passed to 'not applicable' | 1 |
| `19012` | 5 | CIS Benchmark for Amazon Linux 2023 Benchmark v1.0.0.: Ensure sticky bit is set on all world-writable directories.: Status changed from passed to 'not applicable' | 1 |
| `19003` | 5 | SCA summary: CIS Benchmark for Amazon Linux 2023 Benchmark v1.0.0.: Score less than 80% (52) | 1 |
| `31301` | 14 | CRITICAL ATTACK: Remote Code Execution via Web Shell detected | 1 |
| `5712` | 10 | sshd: Brute force attack detected in test simulation. | 1 |
| `19015` | 3 | CIS Benchmark for Amazon Linux 2023 Benchmark v1.0.0.: Ensure sudo is installed.: Status changed from 'not applicable' to passed | 1 |
| `19015` | 3 | CIS Benchmark for Amazon Linux 2023 Benchmark v1.0.0.: Ensure sticky bit is set on all world-writable directories.: Status changed from 'not applicable' to passed | 1 |
| `19003` | 5 | SCA summary: CIS Benchmark for Amazon Linux 2023 Benchmark v1.0.0.: Score less than 80% (53) | 1 |
| `5551` | 10 | PAM: Multiple failed logins in a small period of time. | 1 |
| `5712` | 10 | sshd: brute force trying to get access to the system. Non existent user. | 1 |
| `19011` | 9 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure all AppArmor Profiles are in enforce or complain mode.: Status changed from passed to failed | 1 |
| `19011` | 9 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure sshd GSSAPIAuthentication is disabled.: Status changed from passed to failed | 1 |
| `19011` | 9 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure sshd HostbasedAuthentication is disabled.: Status changed from passed to failed | 1 |
| `19011` | 9 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure sshd IgnoreRhosts is enabled.: Status changed from passed to failed | 1 |
| `19011` | 9 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure sshd LogLevel is configured.: Status changed from passed to failed | 1 |
| `19010` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure sshd MACs are configured.: Status changed from failed to passed | 1 |
| `19011` | 9 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure sshd MaxSessions is configured.: Status changed from passed to failed | 1 |
| `19011` | 9 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure sshd PermitEmptyPasswords is disabled.: Status changed from passed to failed | 1 |
| `19011` | 9 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure sshd PermitUserEnvironment is disabled.: Status changed from passed to failed | 1 |
| `19011` | 9 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure sshd UsePAM is enabled.: Status changed from passed to failed | 1 |
| `19004` | 7 | SCA summary: CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Score less than 50% (47) | 1 |
| `19010` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure sshd GSSAPIAuthentication is disabled.: Status changed from failed to passed | 1 |
| `19010` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure sshd HostbasedAuthentication is disabled.: Status changed from failed to passed | 1 |
| `19010` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure sshd IgnoreRhosts is enabled.: Status changed from failed to passed | 1 |
| `19010` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure sshd LogLevel is configured.: Status changed from failed to passed | 1 |
| `19011` | 9 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure sshd MACs are configured.: Status changed from passed to failed | 1 |
| `19010` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure sshd MaxSessions is configured.: Status changed from failed to passed | 1 |
| `19010` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure sshd PermitEmptyPasswords is disabled.: Status changed from failed to passed | 1 |
| `19010` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure sshd PermitUserEnvironment is disabled.: Status changed from failed to passed | 1 |
| `19010` | 3 | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0.: Ensure sshd UsePAM is enabled.: Status changed from failed to passed | 1 |
| `550` | 7 | Integrity checksum changed. | 1 |
| `202` | 7 | Agent event queue is 90% full. | 1 |
| `203` | 9 | Agent event queue is full. Events may be lost. | 1 |
| `205` | 3 | Agent event queue is back to normal load. | 1 |
| `31120` | 5 | Web server 500 error code (server error). | 1 |

## 4. Daftar Tiket Insiden di Antrean Triage (Top Priority)

| Triage ID | Prio | Status | Tenant | Target Host | Attacker / Process | Judul Insiden |
| :--- | :---: | :---: | :--- | :--- | :--- | :--- |
| `TRG-P0-74B58AC440A0D0A8` | **P0** | OPEN | DEFAULT | `soc-internal-dashboard-86` | `proc:kernel_or_auditd` | [P0] sec_module: systemd | event: process_execution | proc:  |
| `TRG-P0-A0ED3E425D5C8538` | **P0** | OPEN | DEFAULT | `dashboard-multitenant-asoc-103` | `user:root` | [P0] sec_module: sudo | event: process_execution | proc: use |
| `TRG-P0-09DF23BB3B69FE91` | **P0** | OPEN | DEFAULT | `soc-internal-dashboard-86` | `proc:kernel_or_auditd` | [P0] sec_module: systemd | event: process_execution | proc:  |
| `TRG-P0-0274A52F6E7DDFEA` | **P0** | OPEN | DEFAULT | `dashboard-multitenant-asoc-103` | `proc:kernel_or_auditd` | [P0] sec_module: systemd | event: process_execution | proc:  |
| `TRG-P0-2C48BD793B767DCD` | **P0** | OPEN | DEFAULT | `soc-internal-dashboard-86` | `proc:kernel_or_auditd` | [P0] sec_module: systemd | event: process_execution | proc:  |
| `TRG-P0-5BDF6CF04C625D55` | **P0** | OPEN | DEFAULT | `dashboard-multitenant-asoc-103` | `proc:kernel_or_auditd` | [P0] sec_module: systemd | event: process_execution | proc:  |
| `TRG-P1-B0B3315CD8A829E8` | **P0** | OPEN | SOC_CORE | `multitenant-soc-131` | `10.20.100.252` | [P1] auth_type: sshd | event: login_success | actor: user:ub |
| `TRG-P4-2F5C4742783085CD` | **P0** | INVESTIGATE | SOC_CORE | `multitenant-soc-131` | `user:ubuntu` | [P4] auth_type: pam | event: login_session_closed | actor: u |
| `TRG-P1-2304D6E1715F7AD3` | **P0** | OPEN | SOC_CORE | `multitenant-soc-131` | `user:ubuntu` | [P1] auth_type: pam | event: login_success | actor: user:ubu |
| `TRG-P1-036E34047715538E` | **P0** | OPEN | SOC_CORE | `multitenant-soc-131` | `user:root` | [P1] auth_type: pam | event: login_success | actor: user:roo |
| `TRG-P4-37C8DDF0852A8347` | **P0** | INVESTIGATE | TenantC | `hportal-prod-159` | `proc:kernel_or_auditd` | [P4] sec_module: ossec | event: process_execution | proc: pr |
| `TRG-P0-71549A007DCCD9EC` | **P0** | INVESTIGATE | SOC_CORE | `multitenant-soc-131` | `user:root` | [P0] sec_module: sudo | event: process_execution | proc: use |
| `TRG-P4-00B6A0A45281B502` | **P0** | OPEN | SOC_CORE | `multitenant-soc-131` | `user:root` | [P4] auth_type: pam | event: login_session_closed | actor: u |
| `TRG-P1-064A5A4E7EC753FD` | **P0** | OPEN | SOC_CORE | `multitenant-soc-131` | `user:root` | [P1] auth_type: pam | event: login_success | actor: user:roo |
| `TRG-P0-F6C0B65F624AAB6D` | **P0** | OPEN | SOC_CORE | `multitenant-soc-131` | `user:root` | [P0] sec_module: sudo | event: process_execution | proc: use |
| `TRG-P1-AD33E8FC1CC86856` | **P0** | OPEN | SOC_CORE | `multitenant-soc-131` | `user:root` | [P1] auth_type: pam | event: login_success | actor: user:roo |
| `TRG-P4-77C6067B36093294` | **P0** | OPEN | SOC_CORE | `multitenant-soc-131` | `user:root` | [P4] auth_type: pam | event: login_session_closed | actor: u |
| `TRG-P0-2293E8266C47A3CC` | **P0** | OPEN | SOC_CORE | `multitenant-soc-131` | `user:root` | [P0] sec_module: sudo | event: process_execution | proc: use |
| `TRG-P4-0A53814D2D8C9303` | **P0** | OPEN | SOC_CORE | `multitenant-soc-131` | `user:ubuntu` | [P4] auth_type: pam | event: login_session_closed | actor: u |
| `TRG-P4-5DE7045F9B1498D2` | **P0** | OPEN | SOC_CORE | `multitenant-soc-131` | `user:root` | [P4] auth_type: pam | event: login_session_closed | actor: u |
| `TRG-P0-FFDF9956E036A531` | **P0** | OPEN | SOC_CORE | `multitenant-soc-131` | `user:root` | [P0] sec_module: sudo | event: process_execution | proc: use |
| `TRG-P1-CA42D7F9F84A26E8` | **P0** | OPEN | SOC_CORE | `multitenant-soc-131` | `user:root` | [P1] auth_type: pam | event: login_success | actor: user:roo |
| `TRG-P0-9149AE3D66F61379` | **P0** | OPEN | SOC_CORE | `multitenant-soc-131` | `user:root` | [P0] sec_module: sudo | event: process_execution | proc: use |
| `TRG-P4-F02E5A7610EE9376` | **P0** | OPEN | SOC_CORE | `multitenant-soc-131` | `user:root` | [P4] auth_type: pam | event: login_session_closed | actor: u |
| `TRG-P4-44AD5745F4A0E6D8` | **P0** | OPEN | SOC_CORE | `multitenant-soc-131` | `user:root` | [P4] auth_type: pam | event: login_session_closed | actor: u |
| `TRG-P1-55EE1E55548A4FAF` | **P0** | OPEN | SOC_CORE | `multitenant-soc-131` | `user:root` | [P1] auth_type: pam | event: login_success | actor: user:roo |
| `TRG-P0-150A30D9823057D6` | **P0** | OPEN | SOC_CORE | `multitenant-soc-131` | `user:root` | [P0] sec_module: sudo | event: process_execution | proc: use |
| `TRG-P4-CDF2637D3BDBAD9A` | **P0** | OPEN | SOC_CORE | `multitenant-soc-131` | `user:root` | [P4] auth_type: pam | event: login_session_closed | actor: u |
| `TRG-1792049999_8888` | **P0** | INVESTIGATE | TenantA | `web-ecommerce-prod` | `45.33.32.156` | CRITICAL ATTACK: Remote Code Execution via Web Shell detecte |
| `TRG-P1-1E5E6FF525543760` | **P1** | OPEN | DEFAULT | `soc-internal-dashboard-86` | `10.20.100.252` | [P1] auth_type: sshd | event: login_success | actor: user:ub |
| `TRG-P1-0F41727C39F15147` | **P1** | OPEN | DEFAULT | `soc-internal-dashboard-86` | `user:ubuntu` | [P1] auth_type: pam | event: login_success | actor: user:ubu |
| `TRG-P1-C486EC429DD1A6D3` | **P1** | OPEN | DEFAULT | `dashboard-multitenant-asoc-103` | `user:root` | [P1] auth_type: pam | event: login_success | actor: user:roo |
| `TRG-P1-7FD07890D9D87460` | **P1** | OPEN | DEFAULT | `dashboard-multitenant-asoc-103` | `user:ubuntu` | [P1] auth_type: pam | event: login_success | actor: user:ubu |
| `TRG-P1-27C307301FBFE7C5` | **P1** | OPEN | TenantD | `isif-rproxy-155` | `user:root` | [P1] auth_type: pam | event: login_success | actor: user:roo |
| `TRG-P1-106A8F3875A3ADAC` | **P1** | OPEN | TenantC | `Learning-acadcsirt-dimas-123` | `10.20.100.222` | [P1] auth_type: sshd | event: login_success | actor: user:ub |
| `TRG-P1-E44E0D21E0FE3D89` | **P1** | OPEN | TenantC | `Learning-acadcsirt-dimas-123` | `user:ubuntu` | [P1] auth_type: pam | event: login_success | actor: user:ubu |
| `TRG-P1-45DC364EBA0DC6DF` | **P1** | OPEN | DEFAULT | `soc-internal-dashboard-86` | `user:root` | [P1] auth_type: pam | event: login_success | actor: user:roo |
| `TRG-P1-429DD08E86E09B39` | **P1** | OPEN | SOC_CORE | `multitenant-soc-131` | `user:ubuntu` | [P1] auth_type: pam | event: login_success | actor: user:ubu |
| `TRG-P1-51C9762C3006E4FE` | **P1** | OPEN | SOC_CORE | `multitenant-soc-131` | `10.20.100.252` | [P1] auth_type: sshd | event: login_success | actor: user:ub |
| `TRG-P1-2E6A0F38015815A0` | **P1** | OPEN | SOC_CORE | `multitenant-soc-131` | `user:root` | [P1] auth_type: pam | event: login_success | actor: user:roo |
| `TRG-1792125164_457263` | **P1** | OPEN | TenantA | `zabbix-prod-214` | `10.20.100.252` | High amount of POST requests in a small period of time (like |
| `TRG-1792125048_452485` | **P1** | OPEN | TenantA | `zabbix-prod-214` | `10.20.100.252` | High amount of POST requests in a small period of time (like |
| `TRG-1792125006_447761` | **P1** | OPEN | TenantA | `zabbix-prod-214` | `10.20.100.252` | High amount of POST requests in a small period of time (like |
| `TRG-1792124868_441203` | **P1** | OPEN | TenantA | `zabbix-prod-214` | `10.20.100.252` | High amount of POST requests in a small period of time (like |
| `TRG-1792124772_406687` | **P1** | OPEN | TenantA | `zabbix-prod-214` | `10.20.100.252` | High amount of POST requests in a small period of time (like |
| `TRG-1792124744_401881` | **P1** | OPEN | TenantA | `zabbix-prod-214` | `10.20.100.252` | High amount of POST requests in a small period of time (like |
| `TRG-1792124696_396182` | **P1** | OPEN | TenantA | `zabbix-prod-214` | `10.20.100.252` | High amount of POST requests in a small period of time (like |
| `TRG-1792124670_391340` | **P1** | OPEN | TenantA | `zabbix-prod-214` | `10.20.100.252` | High amount of POST requests in a small period of time (like |
| `TRG-1792124650_387046` | **P1** | OPEN | TenantA | `zabbix-prod-214` | `10.20.100.252` | High amount of POST requests in a small period of time (like |
| `TRG-1792124624_381979` | **P1** | OPEN | TenantA | `zabbix-prod-214` | `10.20.100.252` | High amount of POST requests in a small period of time (like |

*(Menampilkan 50 dari total 117 tiket. Data lengkap dapat dibaca di `wazuh_vm_incident_tickets.csv`)*
