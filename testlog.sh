#!/usr/bin/bash

# params either read from stdin or as positional args
if [ -z "$1" ] ; then
  read -p "Protocol [http/ssh/ssl/telnet]: " proto
  read -p "Device name: " devname
  read -p "Firmware version (* for all available): " fwver
  read -p "Operation: " oper
  read -p "Command to run: " cmd
  read -p "Args to replay server: " args
else
  proto="$1"
  devname="$2"
  fwver="$3"
  oper="$4"
  cmd="$5"
  args="$6"
fi

# check protocol validity
if [ ! -d "logs/${proto}" ] ; then
  echo "No such protocol: ${proto}"
  exit 1
fi

# check device validity
if [ ! -d "logs/${proto}/${devname}" ] ; then
  echo "No such device: ${devname}"
  exit 1
fi

# check fw validity
if [ ! "${fwver}" = "*" ] ; then
  if [ ! -d "logs/${proto}/${devname}/${fwver}"] ; then
    echo "No such firmware: ${fwver}"
    exit 1
  fi
fi

# get list of firmwares if fwver == '*' and return those that have logs for given operation
if [ "${fwver}" = '*' ] ; then
  fwlist=$(ls "logs/${proto}/${devname}/")
  for v in ${fwlist} ; do
    if [ -d "logs/${proto}/${devname}/${v}/${oper}" ] ; then
      fw_can_test="${fw_can_test} ${v}"
    fi
  done
  if [ -z "${fw_can_test}" ] ; then
    echo "No firmware to test for operation: ${oper}"
    exit 1
  fi
else
  # check operation validity
  if [ ! -d "logs/${proto}/${devname}/${fwver}/${oper}" ] ; then
    echo "No such operation: ${oper}"
    exit 1
  fi
  fw_can_test="${fwver}"
fi


# test all that can be tested
successful_tests=0
failed_tests=0
cd "${proto}"
for v in ${fw_can_test} ; do
  for i in $(ls ../logs/${proto}/${devname}/${v}/${oper}/) ; do
    echo "Testing ../logs/${proto}/${devname}/${v}/${oper}/${i}"
    ./"${proto}"_replay.py ${args} -f "../logs/${proto}/${devname}/${v}/${oper}/${i}" &
    pid=$!
    sleep 1
    eval "${cmd}"
    result=$?
    wait $pid
    #kill $pid 2>&1 >/dev/null || true
    echo "Exit code: $result"
    if [ $result -eq 0 ] ; then
      ((successful_tests++))
      st="${st} logs/${proto}/${devname}/${v}/${oper}/${i}"
    else
      ((failed_tests++))
      ft="${ft} logs/${proto}/${devname}/${v}/${oper}/${i}"
    fi
    echo
    echo
  done
done
cd ..

echo
echo "====="
echo "Summary: ${successful_tests} tests succeeded, ${failed_tests} failed"
echo "List of failed tests:"
for t in ${ft} ; do
  echo "  $t"
done
