# Dante SOCKS server configuration for Telegram

## Setup

	# mv /etc/danted.conf /etc/danted.conf.orig
	# wget https://raw.githubusercontent.com/roman-rybalko/dante-telegram/master/etc/danted.conf -O /etc/danted.conf
	# addgroup danteuser
	# adduser --shell /usr/sbin/nologin --no-create-home --ingroup danteuser --gecos "" --force-badname pVpRyZNF9QhS
	# adduser --shell /usr/sbin/nologin --no-create-home --ingroup danteuser --gecos "" --force-badname xCJ8stRwbzgR
	# ...
	# service danted stop
	# service danted status
	# service danted start
	# service danted status
	# 
