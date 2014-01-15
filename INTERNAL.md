MITMPROXY LIBRARY INTERNALS
===========================

Introduction
------------
Currently mitmproxy library consists of 2 modules mitmproxy.py and sshdebug.py.
Module mitmproxy.py contains all stuff that implements proxy and replay servers
for supported network protocols. Module sshdebug.py is only little encore to
ssh proxy which prints unencrypted ssh messages in more human readable form
(not one long line hexa number string). It should serve for debugging ssh proxy
and ssh replay server. The library is built on twisted network framework
written in python. For more details see the project homepage
[twistedmatrix.com](http://twistedmatrix.com/).

Supported network protocols
---------------------------
* Telnet
* HTTP
* HTTPS/SSL
* SSH
* SNMP

MITM proxy server in general
----------------------------
`
            +------------------MITM PROXY-----------------------+
+------+    | +------------+   +-------------+   +------------+ |    +------+
|      |    | |   (receive)|<<<|DefferedQueue|<<<|(transmit)  | |    |      |
|      |    | |            |   +-------------+   |            | |    |      |
|Server|<-->| |PROXY Client|                     |PROXY Server| |<-->|Client|
|      |    | |            |   +-------------+   |            | |    |      |
|      |    | |  (transmit)|>>>|DefferedQueue|>>>|(receive)   | |    |      |
+------+    | +------------+   +-------------+   +------------+ |    +------+
            +---------------------------------------------------+
                 |                                         |
                 |------------->   Logfile   <-------------|
`

As you can see on above ascii image MITM proxy has 2 componets proxy server
and proxy client, which communicate between themselves by deffered queues. If
you don't know what deffered queues is, read about Deffereds and Twisted
asynchronous mechanism in documentation page
[defer-intro](http://twistedmatrix.com/documents/current/core/howto/defer-intro.html).
Each proxy component logs communication with its counterpart (client/server)
into logfile. Logfiles is used by replay servers, when they replaying original
server's communication.

If you want understand telnet, html, ssl and snmp proxy, you need to read how
to write TCP/UDP clients and servers with twisted on twisted documentation
pages [doc pages](http://twistedmatrix.com/documents/current/core/howto/index.html).
All proxy based on aforementioned protocols are similiar. Exception is ssh
protocol, because its architecture has tree layers transport, authentication
and connection. SSH proxy and replay are using twisted implementation of SSHv2
from *twisted.conch.ssh* package. There are some examples of ssh clients and
servers on twisted conch documentation pages
[conch doc](http://twistedmatrix.com/documents/current/conch/index.html).
Another twisted.conch.ssh howto can be found on these two links
[ticket-5474](http://twistedmatrix.com/trac/ticket/5474) and
[ticket-6001](http://twistedmatrix.com/trac/ticket/6001).

Notes about SSH proxy and replay server
---------------------------------------
### SSH key pairs
SSH proxy/replay needs generated ssh key-pairs for proxy client and server even
when they aren't used, so generate some defaults with mitmkeygen or set yours
by command line arguments.

### Communication
Proxy components have their own separated encrypted connections with its
intercepted counterparts. Proxy server with client and proxy client with
server. Communication between proxy components starts during authentication.
Proxy server give some information like client's authentication method,
username, public key or password to proxy client and proxy client try to
connect to server. Proxy client inform proxy server about successful or
unsuccessful authentication, so proxy server know how to authenticate client.
When client is authenticated messages belonging ssh connection layer begins
sent between client and server. All these messages from ssh connection layer
are interchanged between proxy client and proxy server and forwarded to its
endpoints. This forwarding does *mitmproxy.ProxySSHConnection* class which
subclassing *ssh.connection.SSHConnection* class. Class overrides method
*packetReceived*. It only puts packets to Deferred Queue and logs some type of
ssh messages (SSH_MSG_CHANNEL_DATA). Original method dispatch messages to
theirs process methods, but proxy don't process messages from this connection
layer only intercepts and forwords. Communication endpoints client and server
does.

### Authentication
Authentication of client through proxy server is the most problematic part.
Proxy server don't know how to authenticate client. It waits for information
from proxy client and then respond to client. Proxy server uses twisted's
plugable authentication system. You can read about it on page [Plugable
Authentication](http://twistedmatrix.com/documents/current/core/howto/cred.html).
Proxy authentication is implemented in these classes:
* ProxySSHUserAuthServer
* ProxySSHUserAuthClient
* SSHCredentialsChecker
Proxy server side is implemented mostly in *SSHCredentialsChecker*. In
*ProxySSHUserAuthServer* is only hack for proper ending communication. Proxy
client gets information like username, authentication method, Deferred Queue
for password. Then authentication result is evaluted in callback method
*mitmproxy.SSHCredentialsChecker.is_auth_succes*. There is three possible
results:
1. authentication is successful
2. authentication failed and there are another authentication methods
3. authentication failed and no more authentication methods
Proxy client authentication is implemented in *ProxySSHUserAuthClient*. It
sends and receives informtion from/to proxy server through deferred queues.
After successful authentication begins ssh-connection service.
There is some issues with proxy authentication:
1. proxy client and client authentications methods attempts order must be same
2. server support less authentication methods than proxy server
First issue is solved with sending name of current authentication method used
by client to proxy client. Second issue is solved by pretend of method failure
and proxy client waits for another authentication method.

One more note to authentication. The proxy authentication tries to be the most
transparent as it goes. All depends only on server and client configuration
(e.g. Number of password prompts).

### SSH Replay server
SSH replay server always authorizates client with first authentication method
attempt. We don't need special security here because replay server should be
used for testing. Replay server is implemented in
*mitmproxy.SSHReplayServerProtocol* and it is connected to ssh service in
*mitmproxy.ReplayAvatar* class.

### SSH proxy drawbacks
It supports only logging of ssh msg channel data messages and sessions with one
opened channel. It doesn't support other ssh features like port forwarding.

Notes about SNMP proxy and replay server
----------------------------------------
SNMP proxy is ordinary UDP server that intercepts and forwards UDP packets.
Because of UDP protocol we don't know when ends communication. You can save PID
of SNMP proxy and when client end you can terminate SNMP proxy. SNMP replay
reads communication from log and compare received packets with expected packets
from log. It copes with different request-ids in packets. There are functions
for extract and replace snmp request-id *snmp_extract_request_id* and
*snmp_replace_request_id*. SNMP proxy logs all kind of UDP messages. SNMP
replay server works only with snmp UDP messages.

