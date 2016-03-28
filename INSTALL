Building and installing
-----------------------

To build on Ubuntu systems, the following packages are needed (tested on
Ubuntu 14.04 Trusty Tahr):
	autoconf
	libtool
	libmozjs-17.0-dev
	libssl-dev


Obsolete build instructions
---------------------------

# yum install git spamassassin screen
# chkconfig spamassassin on
# service spamassassin start
# yum install make gcc autoconf automake libtool ElectricFence
# yum install libconfig-devel postgresql-devel openssl-devel
# groupadd -dd -g 480 mailfilter
# useradd -s /sbin/nologin -d /opt/mailfilter -g mailfilter -u 480 -M mailfilter
# cd /opt/
# git clone git://git.mindbit.ro/mailfilter.git
# chown mailfilter: -R mailfilter/
# screen
# su -s /bin/bash - mailfilter
$ ./autogen.sh
$ ./configure
$ vim src/mod_proxy.c         # edit proxy_host and/or proxy_port; default: 10.127.0.1:25
$ vim src/smtp_server.c       # look for smtp_server_init() and see what modules you need
$ make
$ cp mailfilter.conf.default mailfilter.conf
$ vim mailfilter.conf         # logging: type = "syslog"; level = "debug"; facility = "mail";
                              # dbconn: look at /usr/lib/mipanel/backend/model/build/conf/mipanel-conf.php
$ ulimit -c unlimited
$ ./src/mailfilter -c mailfilter.conf
