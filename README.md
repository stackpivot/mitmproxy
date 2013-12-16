MITM Proxy
==========
A collection of multi-protocol logging proxy servers and replay utilities.

Supported protocols:
  * Telnet
  * HTTP
  * SSL
  * SSH

License
-------
Distributed under the GNU General Public License version 2 (GPLv2).

Dependencies
------------
* Python 2.7
* Twisted Python library (python-twisted)

Motivation
----------
Created as a debugging tool for various enterprise fencing agents that tend
to break with each fencing device firmware upgrade, and then again (after
fixing for the new FW) for older firmware versions. :)


Protocol-specific notes
=======================

Telnet
------
Nothing fancy.

HTTP
----
* Best to run it as

  ```
  while true; do mitmproxy_http [options]; done
  ```

  * That's because the proxy terminates after each connection close, which might be OK for some limited amount of tools, but completely unusable with full-blown browsers and such

* Support for relative links, not absolute
  * When the real client sees absolute link, it creates a new, direct connection to the real server (can be overriden via /etc/hosts for local clients; DNS spoofing otherwise)
  * The above also fixes the `Host` HTTP header
  * However, make sure you're using IP address as an argument to -H option when going the /etc/hosts way! (infinite recursion FTW!)

* Must bind to port 80 (or whatever the real server is running at) to be compatible with redirects and absolute/relative links
  * Either run proxy as root (dirty and insecure) or use authbind / iptables / selinux

SSL
---
* Need to have server keys generated (mitmkeygen)
* HTTP notes also apply to SSL
* Connect with SSL:

```
openssl s_client -connect localhost:4443
```

SSH
---
* Supports pubkey and password auth (not eg. keyboard-interactive)
* Requires generated keys (mitmkeygen)
* Make sure server accepts the generated pubkey if using pubkey auth (eg. with `ssh-copy-id -i ~/.mitmkeys/id_rsa user@host`)
* SSH password is neither saved in the log, nor shown on the screen (unless overriden by commandline option).
* Client's SSH pubkey is ignored, proxy replaces it by its own.
* Password is forwarded without problems.
* SSH client will see MITM warning if it connected to the real server before (cached server host key fingerprint). If it's connecting for the first time, then... ;)
* You can have separate keypairs for client/server, just use the -a/-A and -b/-B options (mnemonic: Alice is the client, Bob the server; pubkey is not a big deal, privkey is ;))


Example Usage
-------------
* Fencing-specific usage
  * Launch the logging proxy server and fence agent.

    ```
    $ mitmproxy_telnet -H apc.example.com -o fencing_apc.log &
    $ fence_apc -a localhost -u 2323 -l login -p password -n 1
    ```

    APC plug #1 will be powered off and on again and we'll have the session log.
  
  * Replay the log at twice the speed.

    ```
    $ mitmreplay_telnet -f fencing_apc.log -d 0.5 &
    $ fence_apc -a localhost -u 2323 -l user -p password -n 1
    [...]
    ERROR: Expected 6d6f67696e0d000a (login...), got 757365720d000a (user...).
    FAIL! Premature end: not all messages sent.
    Client disconected.

    Unable to connect/login to fencing device
    ```

    Oops, wrong username. ;)

* Log viewer usage
  * The log viewer displays the whole session in real time or with an optional time dilation.
  
  ```
  $ mitmlogview -f fencing_apc.log -d 10
  ```

* Log diff usage
  * Shows the diff of two logs in vimdiff without comparing the timestamps.

  ```
  $ mitmlogdiff fencing_apc.log other_fencing_apc.log
  ```
