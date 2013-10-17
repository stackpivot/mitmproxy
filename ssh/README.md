DESCRIPTION
===========
ssh_proxy.py:
    * SSH proxy server, that logs interactive session communication.

SUPPORTED AUTHENTICATION
========================
publickey:  YES
password:   YES
other:      NO

LOGGING
=======
SSH_MSG_CHANNEL_DATA payloads only

USAGE
=====
1. Generate keys.
    cd keys && sh keys/keygen.sh && cd ..
2. Copy public key on server, which you want to connect.
    ssh-copy-id -i keys/id_rsa username@hostname
3. Read the help.
    ./ssh_proxy.py --help
4. Start proxy server.
    e.g:
    ./ssh_proxy.py -host=localhost --port=22 -local-port=2222
5. Connect to proxy server with identity keys/client.
    e.g.:
    ssh -i keys/id_rsa -p 2222 testmonkey@localhost
5. ???
6. Profit!
