#!/usr/bin/bash

echo ">>>Generating proxy and client key pairs..."

ssh-keygen -q -N "" -C proxy@mitm -f ./proxy
ssh-keygen -q -N "" -C client@mitm -f ./client

echo ">>>Keys proxy, proxy.pub, client, client.pub was created."
echo ">>>Done."
