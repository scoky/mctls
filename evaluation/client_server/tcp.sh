#!/bin/bash

# Add this code to client, middlebox, and server to disable Nagle algorithm
#int flag=1;
#if (setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int)) < 0)
#	exit(0);

sudo sysctl net.ipv4.tcp_rmem="8192 8388608 16777216"
sudo sysctl net.ipv4.tcp_wmem="8192 8388608 16777216"
sudo sysctl net.ipv4.route.flush=1
sudo ip route change default via 192.168.1.1 dev wlan0 proto static initcwnd 40
