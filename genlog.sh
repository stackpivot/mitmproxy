#!/usr/bin/bash

home=$(dirname $0)

# params either read from stdin or as positional args
if [ -z "$1" ] ; then
  read -p "Protocol [http/ssh/ssl/telnet]: " proto
  read -p "Device name: " devname
  read -p "Firmware version: " fwver
  read -p "Operation: " oper
  read -p "Args to proxy: " args
else
  proto="$1"
  devname="$2"
  fwver="$3"
  oper="$4"
  args="$5"
fi

# make dir structure if it does not exist
mkdir -p "${home}/logs/${proto}/${devname}/${fwver}/${oper}/"

# calculate next log index/filename (for multiple samples of same protocol/device/fw/operation)
# will default to 1 of no logs exist yet
files=$(ls "${home}/logs/${proto}/${devname}/${fwver}/${oper}/" | grep '[[:digit:]]*\.log' | sed 's/\.log//')
lastindex=$(echo "$files" | tac | head -n 1)
nextindex=$((lastindex+1))
newlog="${home}/logs/${proto}/${devname}/${fwver}/${oper}/${nextindex}.log"

# print the log name
echo "Saving log to ${newlog}"

${home}/"${proto}"_proxy.py ${args} -o "${newlog}"

echo "Done."
