SSH INTERCEPTOR
===============


SUPPORTED AUTH METHODS
----------------------
* publickey:  YES
* password:   YES
* other:      NO (maybe keyboard-interactive in the future?)


USAGE
-----

1. Generate fake client/server keypairs if you don't have them already (empty password for ssh key; ssl cert password doesn't matter, will be stripped)

    ```
    mkdir ~/.mitmkeys && cp keys/keygen.sh ~/.mitmkeys/ && cd ~/.mitmkeys && ./keygen.sh
    ```

2. Copy the newly generated public key to server (Z0MG L33T H4X!!!1)

    ```
    ssh-copy-id -i ~/.mitmkeys/id_rsa user@host
    ```

4. Start proxy server, eg. to intercept traffic for `host`

    ```
    proxy_ssh.py -H host
    ```

5. Connect through the proxy

    ```
    ssh user@localhost -p 2222
    ```

5. ???

6. Profit!


NOTES
-----

* SSH password is neither saved in the log, nor shown on the screen (unless overriden by commandline option).
* Client's SSH pubkey is ignored, proxy replaces it by its own.
* Server must accept proxy's pubkey (if using pubkey auth).
* Password is forwarded without problems.
* SSH client will see MITM warning if it connected to the real server before (cached server host key fingerprint). If it's connecting for the first time, then... ;)
* You can have separate keypairs for client/server, just use the -a/-A and -b/-B options (mnemonic: Alice is the client, Bob the server; pubkey is not a big deal, privkey is ;))
