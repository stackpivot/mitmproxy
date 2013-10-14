#!/usr/bin/bash
ssh-keygen -f ./id_rsa
if [ $? -eq 0 ] ; then
  echo "Keypair successfully generated."
else
  echo "Something went wrong..."
fi
