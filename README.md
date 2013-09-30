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


Motivation
----------
Created as a debugging tool for various enterprise fencing agents that tend
to break with each fencing device firmware upgrade, and then again (after
fixing for the new FW) for older firmware versions. :)

Example usage
-------------
* Launch the logging proxy server
```
$ cd telnet
$ ./telnet_proxy.py -H example.com -o telnet.log
Server running on localhost:2323...
```

* Open another terminal and telnet to our proxy
```
$ telnet localhost 2323 < commands.txt
```
Proxy prints info about client connecting, connection attempt
to the real server, and eventually disconnect both ends after
the conversation ends.

* Start the replay server with the created log file (slowed down by a factor of 3)
```
$ ./telnet_replay.py -f telnet.log -d 3 -o /dev/null
Server running on localhost:2323
```

* Telnet into the replay server with the same commands (should succeed)
```
$ telnet localhost 2323 < commands.txt
```
Proxy prints the usual connection info and a "success" message.

* Try it with a different set of commands (should fail and print the difference)
```
$ telnet localhost 2323 < othercommands.txt
```
...and the replay server says:
```
ERROR: Expected [blah-blah], got [different-blah-blah].
FAIL! Premature end: not all messages sent.
```
