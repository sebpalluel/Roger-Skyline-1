# Roger-Skyline-1
Roger-Skyline-1 42

# Secure VM setup

+ install debian on VM
http://www.brianlinkletter.com/installing-debian-linux-in-a-virtualbox-virtual-machine/

+ resize partition to 4.2gb:
Use cmd cfdisk to delete and reformat to 4.2G

+ give user sudo rights
`adduser roger` -> mdp roger
`adduser roger sudo`

+ configure VM with host only network and static IP
- find default gateway of host, in case of cluster 2 it's 10.12.254.254
`netstat -rn`
https://www.codesandnotes.be/2018/10/16/network-of-virtualbox-instances-with-static-ip-addresses-and-internet-access/:w
put network to bridged adapter en0
gateway 10.12.254.254
address 10.12.1.135
+ netmask /30
255.255.255.252
http://unixwiz.net/techtips/netmask-ref.html
put in /resolve.conf
`nameserver 10.12.254.254`

	+ Make port forwarding in VM config of Virtualbox
Forward ports 80 (HTTP) 443(HTTPS)

	+ connect to VM with SSH from a Mac OS host
	https://www.quora.com/How-can-I-ssh-into-my-VM-from-the-Mac-OS-X-host

	+ configure ssh
	change for port 5050 in /etc/ssh/sshd_config and restart service
	ssh roger@10.12.1.135 -p 5050
	http://blog.johannesmp.com/2017/01/25/port-forwarding-ssh-from-virtualbox/
https://www.linode.com/docs/security/authentication/use-public-key-authentication-with-ssh/
```
port 5050
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentification no
```

+ configure firewall
- UFW to easily set iptables and fail2ban
https://blog.vigilcode.com/2011/04/ubuntu-server-initial-security-quick-secure-setup-part-i/
https://blog.vigilcode.com/2011/05/ufw-with-fail2ban-quick-secure-setup-part-ii/
- Change OpenSSH port to 5050 in /etc/ufw/applications.d
```bash
ufw default deny incoming
ufw default allow outgoing
ufw app list
ufw allow OpenSSH
ufw allow 'Nginx Full'
ufw allow DNS
ufw allow 443
ufw enable
```

- Allow nginx for both http and https:
https://www.digitalocean.com/community/tutorials/how-to-install-nginx-on-ubuntu-16-04

+ configure fail2ban

- config files for fail2ban with nginx, compatible with ufw settings
https://gist.github.com/JulienBlancher/48852f9d0b0ef7fd64c3
https://www.digitalocean.com/community/tutorials/how-to-protect-an-nginx-server-with-fail2ban-on-ubuntu-14-04
https://github.com/mitchellkrogza/Fail2Ban.WebExploits

`sudo wget https://raw.githubusercontent.com/mitchellkrogza/Fail2Ban.WebExploits/master/webexploits.conf -O /etc/fail2ban/filter.d/webexploits.conf`


/etc/fail2ban/jail.local:
```
[DEFAULT]

ignoreip = 127.0.0.1/8 10.12.1.135/30
bantime = 3600
findtime = 86400
maxretry = 6
mta = mail
destemail = root@localhost
sendername = Fail2BanAlerts
banaction = ufw
action = %(action_mwl)s

[webexploits]
enabled  = true
port     = http,https
filter   = webexploits
logpath = %(nginx_access_log)s
maxretry = 3

[sshd]
enabled = true
port    = 5050
logpath = %(sshd_log)s
backend = %(sshd_backend)s

[nginx-req-limit]

enabled = true
filter = nginx-req-limit
action = iptables-multiport[name=ReqLimit, port="http,https", protocol=tcp]
logpath = /var/log/nginx/*error.log
findtime = 600
bantime = 7200
maxretry = 10

[nginx-http-auth]

enabled  = true
filter   = nginx-http-auth
port     = http,https
logpath  = /var/log/nginx/error.log

[nginx-noscript]

enabled  = true
port     = http,https
filter   = nginx-noscript
logpath  = /var/log/nginx/access.log
maxretry = 6

[nginx-badbots]

enabled  = true
port     = http,https
filter   = nginx-badbots
logpath  = /var/log/nginx/access.log
maxretry = 2

[nginx-nohome]

enabled  = true
port     = http,https
filter   = nginx-nohome
logpath  = /var/log/nginx/access.log
maxretry = 2

[nginx-noproxy]

enabled  = true
port     = http,https
filter   = nginx-noproxy
logpath  = /var/log/nginx/access.log
maxretry = 2
```

- protect ssh from ddos with fail2ban:
https://www.digitalocean.com/community/tutorials/how-to-protect-ssh-with-fail2ban-on-centos-7

- protect nginx from ddos:
https://easyengine.io/tutorials/nginx/fail2ban

- activate fail2ban
`sudo systemctl enable fail2ban`

- command to debug fail2ban
`/usr/bin/fail2ban-client -v -v start`

- get status of fail2ban
`sudo fail2ban-client status`
`sudo systemctl status fail2ban`

+ configure portsentry (and test with nmap)
https://www.computersecuritystudent.com/UNIX/UBUNTU/1204/lesson14/index.html
- test ports:
`nmap -p 1-65535 -T4 -A -v -PE -PS22,25,80 -PA21,23,80 -Pn 10.12.1.135`
- check attackalert from portsentry on VM
`grep "attackalert" /var/log/syslog`
- configure TCP and UDP modes to advanced detection:
https://www.tldp.org/LDP/solrhe/Securing-Optimizing-Linux-RH-Edition-v1.3/chap14sec118.html
change in /etc/default/portsentry
```
TCP_MODE="atcp"
UDP_MODE="audp"
```
- https://www.noobunbox.net/serveur/securite/installer-et-configurer-portsentry-debian-ubuntu
change in /etc/portsentry/portsentry.conf
```
BLOCK_UDP="1"
BLOCK_TCP="1"
KILL_ROUTE="/sbin/iptables -I INPUT -s $TARGET$ -j DROP"
KILL_HOSTS_DENY="ALL: $TARGET$ : DENY"
KILL_RUN_CMD=""/sbin/iptables -I INPUT -s $TARGET$ -j DROP && /sbin/iptables -I INPUT -s $TARGET$ -m limit --limit 3/minute --limit-burst 5 -j LOG --log-level debug --log-prefix 'Portsentry: dropping: '"
PORT_BANNER="** UNAUTHORIZED ACCESS PROHIBITED *** YOUR CONNECTION ATTEMPT HAS BEEN LOGGED. GO AWAY."
```
restart portsentry
`service portsentry restart`
check status of portsentry
`service portsentry status`

+ after nmap, host ip should be blocked
`route -n`
to deblock do
`route del 10.12.1.135 reject`
or and
check `/etc/hosts.deny` and remove blocked ip
reboot system

+ disable unused services
https://www.digitalocean.com/community/tutorials/how-to-use-systemctl-to-manage-systemd-services-and-units
- list of services with status
`sudo service --status-all`
install `sysv-rc-conf`
- command to disable a SERVICE
`sudo update-rc.d SERVICE disable`
- check package utility and remove if not necessary https://packages.debian.org

## configure cron
+ dailyUpdate.sh
```bash
\#!/bin/bash

UPDATE="/var/log/update_script.log"

if [ ! -f $UPDATE ]
then
sudo touch $UPDATE;
sudo chmod 666 $UPDATE;
fi
sudo apt update > $UPDATE && sudo apt upgrade -y >> $UPDATE
```
+ warnCronModify.sh
```bash
\#!/bin/bash

BACKUP=/etc/crontab.back

if [ ! -f $BACKUP ]
then
sudo touch $BACKUP;
sudo chmod 666 $BACKUP;
fi
if [ $(sudo md5sum $BACKUP | cut -d ' ' -f1) == $(sudo md5sum /etc/crontab | cut -d ' ' -f1) ]
then
echo \"crontab has not been modified\";
else
echo \"Warning ! crontab has been modified !\";
echo \"Warning ! crontab has been modified !\" | mailx -s "crontab modified" root;
fi
sudo cp /etc/crontab $BACKUP;
```
+ configure email
`sudo apt install mailutils`
command to see mails `mailx`
https://ethereal.email/messages
hipolito.lynch56@ethereal.email
5sKrrhe8z31ZgC59th

+ make scripts executable with chmod +x

+ put in /etc/crontab
```bash
@reboot root /etc/cron.d/dailyUpdate.sh
0 4 * * 1 root /etc/cron.d/dailyUpdate.sh
0 0 * * * root /etc/cron.d/warnCronModif.sh
```
+ check mails in /var/mail/roger

# Server and Site with SSL
+ configure nginx
- https://medium.com/@jgefroh/a-guide-to-using-nginx-for-static-websites-d96a9d034940
## configure ssl
https://www.techrepublic.com/article/how-to-enable-ssl-on-nginx/
1. generate key and cert with openssl
`sudo openssl req -x509 -nodes -newkey rsa:2048 -keyout /etc/ssl/private/nginx-selfsigned.key -out /etc/ssl/certs/nginx-selfsigned.crt`
2. configure pem with dhparams
`openssl dhparam -out /etc/nginx/dhparam.pem 4096`
https://security.stackexchange.com/questions/94390/whats-the-purpose-of-dh-parameters
3. add links for self-signed certificate for nginx in this file /etc/nginx/snippets/self-signed.conf
```
ssl_certificate /etc/ssl/certs/nginx-selfsigned.crt;
ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;
```
4. create a ssl-params.conf file in same snippets location
https://cipherli.st/
```
ssl_protocols TLSv1.2;# Requires nginx >= 1.13.0 else use TLSv1.2
ssl_prefer_server_ciphers on;
ssl_dhparam /etc/nginx/dhparam.pem; # openssl dhparam -out /etc/nginx/dhparam.pem 4096
ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384;
ssl_ecdh_curve secp384r1; # Requires nginx >= 1.1.0
ssl_session_timeout  10m;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off; # Requires nginx >= 1.5.9
ssl_stapling on; # Requires nginx >= 1.3.7
ssl_stapling_verify on; # Requires nginx => 1.3.7
resolver 8.8.8.8 10.12.254.254 valid=300s;
resolver_timeout 5s;
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
add_header X-Frame-Options DENY;
add_header X-Content-Type-Options nosniff;
add_header X-XSS-Protection "1; mode=block";<Paste>
```

5. remove unnecessary services:
`sudo service --status-all`
stop dbus exim4 kmod procps rsyslog udev

## configure auto-deployment of site on nxing server
+ configure vue app with Pm2 :
- https://medium.com/@kamerk22/deploy-vue-js-ssr-vuetify-on-production-with-pm2-and-nginx-ec7b5c0748a3

-  put config for nginx
create this file /etc/nginx/sites-available/psebasti.conf
```
server {
	listen 10.12.1.135:443 ssl;
	include snippets/self-signed.conf;
	include snippets/ssl-params.conf;

	root /var/www/psebasti;

# Add index.php to the list if you are using PHP
	index index.html index.htm index.nginx-debian.html index.php;

	server_name 10.12.1.135;

	location / {
		try_files $uri $uri/ =404;
	}

}
server {
	listen 10.12.1.135:80;
	server_name 10.12.1.135;

	return 301 https://$server_name$request_uri;
}
```

change file `/etc/nginx/nginx.conf` for :

```
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
worker_connections 768;
# multi_accept on;
}

http {

##
# Basic Settings
##

# Max Request for IP
limit_req_zone $binary_remote_addr zone=flood:10m rate=10r/s;
limit_req zone=flood burst=100 nodelay;

# Max Connection for IP
limit_conn_zone $binary_remote_addr zone=ddos:10m;
limit_conn ddos 100;

# SlowLoris protection
client_body_timeout 5s;
client_header_timeout 5s;


sendfile on;
tcp_nopush on;
tcp_nodelay on;
keepalive_timeout 65;
types_hash_max_size 2048;
# server_tokens off;

# server_names_hash_bucket_size 64;
# server_name_in_redirect off;

include /etc/nginx/mime.types;
default_type application/octet-stream;

##
# SSL Settings
##

ssl_protocols TLSv1 TLSv1.1 TLSv1.2; # Dropping SSLv3, ref: POODLE
ssl_prefer_server_ciphers on;

##
# Logging Settings
##

access_log /var/log/nginx/access.log;
error_log /var/log/nginx/error.log;

##
# Gzip Settings
##

gzip on;
gzip_disable "msie6";

# gzip_vary on;
# gzip_proxied any;
# gzip_comp_level 6;
# gzip_buffers 16 8k;
# gzip_http_version 1.1;
# gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

##
# Virtual Host Configs
##

include /etc/nginx/conf.d/*.conf;
			   include /etc/nginx/sites-enabled/*;
			   }


#mail {
#	# See sample authentication script at:
#	# http://wiki.nginx.org/ImapAuthenticateWithApachePhpScript
#
#	# auth_http localhost/auth.php;
#	# pop3_capabilities "TOP" "USER";
#	# imap_capabilities "IMAP4rev1" "UIDPLUS";
#
#	server {
#		listen     localhost:110;
#		protocol   pop3;
#		proxy      on;
#	}
#
#	server {
#		listen     localhost:143;
#		protocol   imap;
#		proxy      on;
#	}
#}
```

test config with `nginx -t`

+ test site deployment
- create file `index.html` in `/var/www/psebasti` and put 'Hello World'
- reload nginx
`sudo systemctl reload nginx`
- put `10.12.1.135` in browser, should display the sentence

+ install nodejs for debian
https://www.digitalocean.com/community/tutorials/how-to-install-node-js-on-debian-8
+ install vuejs boilerplate with vue-cli and build it for production
`npm install && npm run build`
+ change root path in psebasti.conf for `root /var/www/psebasti/vue-test-autodeploy/dist;`
+ guide for CI/CD embedded in gitlab
https://docs.gitlab.com/ee/ci/introduction/index.html
+ Autodeployment on remote server with gitlab CI // can't use here because it require a password for the docker container to be able to connect...
https://msdalp.github.io/2018/06/20/Gitlab-CI-Auto-Deployment-to-Remote-Server/
+ How To Use Git Hooks To Automate Development and Deployment Tasks
https://www.digitalocean.com/community/tutorials/how-to-use-git-hooks-to-automate-development-and-deployment-tasks
+ auto-deployment can be done with https://www.ansible.com/


## to change
- add partition of 4.2gb
check with `fdisk -l`
- services to disable
- check DNS attack with successive hard refresh of web page
`sudo fail2ban-client status`
check when banned
`sudo cat /var/log/fail2ban.log`
`sudo fail2ban-client set nginx-req-limit unbanip 10.12.10.17`
- change portsentry rule in `/etc/portsentry/portsentry.conf`:
uncomment this one `KILL_ROUTE="/sbin/iptables -I INPUT -s $TARGET$ -j DROP"`
- add rule in ufw for DNS :
`sudo ufw allow DNS`
- check portsentry with `nmap 10.12.1.135`
when banned go to VM and do `sudo iptables -L` to show ban and do `sudo iptables -D INPUT 1` to remove ban
also remove ban in `/etc/hosts.deny` and do `sudo service ssh restart`
