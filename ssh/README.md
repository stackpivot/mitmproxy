DESCRIPTION
===========
ssh_proxy.py:
    * SSH proxy server, that logs interactive session communication.

SUPPORTED AUTHENTICATION
========================
publickey:  YES
password:   NO (comming soon;-)
other:      NO

LOGGING
=======
SSH_MSG_CHANNEL_DATA payloads only

USAGE
=====
1. Generate keys.
    sh keys/keygen.sh
2. Copy public key on server, which you want to connect.
    ssh-copy-id -i keys/id_rsa username@hostname
3. Start proxy server. Read the help.
    ./ssh_proxy.py --help
4. Connect to proxy server with identity keys/client.
    e.g.:
    ssh -i keys/id_rsa -p 2222 testmonkey@localhost
5. ???
6. Profit!
