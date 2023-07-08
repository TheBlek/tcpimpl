#!/bin/sh

./run.sh > res.txt &
pid = $!
sleep 3
echo "Hello from 5000" | nc 10.0.0.2 5000
echo "Hello from 5200" | nc 10.0.0.2 5200
trap "kill $pid" SIGINT
wait $pid

if [ "$(cat res.txt)" != "Hello from 5200\nHello from 5000" ]
then
    echo "WRONG!"
fi
