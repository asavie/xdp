#!/bin/sh

nmcli d set eth1 managed no
nmcli d set eth2 managed no
ip addr flush eth1
ip addr add 192.168.100.1/24 dev eth1
ip addr flush eth2
ip addr add 192.168.200.1/24 dev eth2

for ifi in eth1 eth2; do
	for opt in gro lro tso gso; do
		ethtool -K $ifi $opt off
	done
done
