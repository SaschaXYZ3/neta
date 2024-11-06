#!/bin/bash

### Flush existing rules ###
iptables -F
iptables -t nat -F
iptables -t mangle -F
iptables -X
iptables -t nat -F PREROUTING
iptables -t nat -F POSTROUTING

### Default policies: Drop all incoming, outgoing, and forwarded traffic unless allowed ###
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

### Web server rule: Only allow responses to HTTP requests (port 80) ###
# Assuming Web server is at 192.168.1.10
# Allow incoming HTTP requests to the Web server
iptables -A INPUT -p tcp -d 192.168.1.10 --dport 80 -m state --state NEW -j ACCEPT
# Allow outgoing responses from the Web server for established connections
iptables -A OUTPUT -p tcp -s 192.168.1.10 --sport 80 -m state --state ESTABLISHED -j ACCEPT

### DNS server rule: Only allow responses to DNS requests (port 53) ###
# Assuming DNS server is at 192.168.1.20
# Allow incoming DNS requests (UDP and TCP) to the DNS server
iptables -A INPUT -p udp -d 192.168.1.20 --dport 53 -m state --state NEW -j ACCEPT
iptables -A INPUT -p tcp -d 192.168.1.20 --dport 53 -m state --state NEW -j ACCEPT
# Allow outgoing DNS responses from the DNS server for established connections
iptables -A OUTPUT -p udp -s 192.168.1.20 --sport 53 -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp -s 192.168.1.20 --sport 53 -m state --state ESTABLISHED -j ACCEPT

### Internal Network Hosts: Restrict to HTTP connections only ###
# Allow internal hosts to initiate HTTP (port 80) connections to the Internet
iptables -A FORWARD -s 192.168.1.0/24 -p tcp --dport 80 -m state --state NEW -j ACCEPT
# Allow return HTTP traffic to the internal hosts
iptables -A FORWARD -d 192.168.1.0/24 -p tcp --sport 80 -m state --state ESTABLISHED -j ACCEPT
# Enable NAT for outgoing HTTP connections from internal network to the Internet
iptables -t nat -A POSTROUTING -s 192.168.1.0/24 -o ens18 -j MASQUERADE

### Allow established and related connections ###
# Allow established and related connections for INPUT, OUTPUT, and FORWARD
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT 

### Allow traffic on the loopback interface ###
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
