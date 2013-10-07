MITM Proxy
==========
A collection of multi-protocol logging proxy servers and replay utilities.

Supported protocols:
  * Telnet
  * HTTP
  * SSL
  * SSH - soon

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

Example Usage
-------------
* Fencing-specific usage
  * Launch the logging proxy server and fence agent.

    ```
    $ cd telnet
    $ ./telnet_proxy.py -H apc.example.com -o fencing_apc.log &
    $ fence_apc -a localhost -u 2323 -l login -p password -n 1
    ```

    APC plug #1 will be powered off and on again and we'll have the session log.
  
  * Replay the log at twice the speed.

    ```
    $ ./telnet_replay.py -f fencing_apc.log -d 0.5 &
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
  $ ./logviewer.py -f fencing_apc.log -d 10
  ```

* Log diff usage
  * Shows the diff of two logs in vimdiff without comparing the timestamps.

  ```
  $ ./logdiff.sh fencing_apc.log other_fencing_apc.log
  ```
