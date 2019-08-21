#!/bin/sh

nmcli d set eth1 managed no
ip addr add 192.168.200.10/24 dev eth1
ip route del default
ip route add default via 192.168.200.1 dev eth1
arp -s 192.168.200.1 08:00:27:c5:9c:11
