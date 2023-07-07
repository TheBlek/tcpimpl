#!/bin/bash
cargo b
sudo setcap cap_net_admin=eip target/debug/tcpimpl
target/debug/tcpimpl &
pid=$!
# sudo ip addr add 10.0.0.2/24 dev tun0
sudo ip link set up dev tun0
trap "kill $pid" SIGINT 
wait $pid
