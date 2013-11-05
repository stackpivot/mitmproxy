#!/usr/bin/env python2.7
'''
Common MITM proxy classes.
'''

from twisted.internet import protocol, reactor, defer

# Twisted imports for SSH.
from twisted.cred import checkers, credentials, portal
from twisted.conch import avatar, error, interfaces
from zope.interface import implements
from twisted.conch.ssh import connection, factory, keys, \
                              transport, userauth, session

import Queue
import optparse
import time
import sys
import string
import re
import os

# "undefined" class members, attributes "defined" outside init
# pylint: disable=E1101, W0201


def terminate():
    '''
    Shutdown the twisted reactor
    '''
    if reactor.running:
        reactor.stop()


class MITMException(Exception):
    '''
    Custom exception class for MITM proxy
    '''
    pass


def proxy_option_parser(port, localport):
    '''
    Default option parser for MITM proxies
    '''
    parser = optparse.OptionParser()
    parser.add_option(
        '-H', '--host', dest='host', type='string',
        metavar='HOST', default='localhost',
        help='Hostname/IP of real server (default: %default)')
    parser.add_option(
        '-P', '--port', dest='port', type='int',
        metavar='PORT', default=port,
        help='Port of real server (default: %default)')
    parser.add_option(
        '-p', '--local-port', dest='localport', type='int',
        metavar='PORT', default=localport,
        help='Local port to listen on (default: %default)')
    parser.add_option(
        '-o', '--output', dest='logfile', type='string',
        metavar='FILE', default=None,
        help='Save log to FILE instead of writing to stdout')
    opts, args = parser.parse_args()
    return (opts, args)


def ssh_proxy_option_parser(port, localport):
    '''
    Option parser for SSH proxy
    '''
    parser = optparse.OptionParser()
    parser.add_option(
        '-H', '--host', dest='host', type='string',
        metavar='HOST', default='localhost',
        help='Hostname/IP of real server (default: %default)')
    parser.add_option(
        '-P', '--port', dest='port', type='int',
        metavar='PORT', default=port,
        help='Port of real server (default: %default)')
    parser.add_option(
        '-p', '--local-port', dest='localport', type='int',
        metavar='PORT', default=localport,
        help='Local port to listen on (default: %default)')
    parser.add_option(
        '-o', '--output', dest='logfile', type='string',
        metavar='FILE', default=None,
        help='Save log to FILE instead of writing to stdout')
    parser.add_option(
        '-a', '--client-pubkey', dest='clientpubkey', type='string',
        metavar='FILE', default='keys/id_rsa.pub',
        help='Use FILE as the client pubkey (default: %default)')
    parser.add_option(
        '-A', '--client-privkey', dest='clientprivkey', type='string',
        metavar='FILE', default='keys/id_rsa',
        help='Use FILE as the client privkey (default: %default)')
    parser.add_option(
        '-b', '--server-pubkey', dest='serverpubkey', type='string',
        metavar='FILE', default='keys/id_rsa.pub',
        help='Use FILE as the server pubkey (default: %default)')
    parser.add_option(
        '-B', '--server-privkey', dest='serverprivkey', type='string',
        metavar='FILE', default='keys/id_rsa',
        help='Use FILE as the server privkey (default: %default)')
    parser.add_option(
        '-s', '--show-password', dest='showpassword', action='store_true',
        default=False,
        help='Show SSH password on the screen (default: %default)')
    opts, args = parser.parse_args()
    return (opts, args)


def replay_option_parser(localport):
    '''
    Default option parser for replay servers
    '''
    parser = optparse.OptionParser()
    parser.add_option(
        '-p', '--local-port', dest='localport', type='int',
        metavar='PORT', default=localport,
        help='Local port to listen on (default: %default)')
    parser.add_option(
        '-f', '--from-file', dest='inputfile', type='string',
        metavar='FILE', default=None,
        help='Read session capture from FILE instead of STDIN')
    parser.add_option(
        '-o', '--output', dest='logfile', type='string',
        metavar='FILE', default=None,
        help='Log into FILE instead of STDOUT')
    parser.add_option(
        '-d', '--delay-modifier', dest='delaymod', type='float',
        metavar='FLOAT', default=1.0,
        help='Modify response delay (default: %default)')
    opts, args = parser.parse_args()
    return (opts, args)


def ssh_replay_option_parser(localport):
    '''
    Option parser for SSH replay server
    '''
    parser = optparse.OptionParser()
    parser.add_option(
        '-p', '--local-port', dest='localport', type='int',
        metavar='PORT', default=localport,
        help='Local port to listen on (default: %default)')
    parser.add_option(
        '-f', '--from-file', dest='inputfile', type='string',
        metavar='FILE', default=None,
        help='Read session capture from FILE instead of STDIN')
    parser.add_option(
        '-o', '--output', dest='logfile', type='string',
        metavar='FILE', default=None,
        help='Log into FILE instead of STDOUT')
    parser.add_option(
        '-d', '--delay-modifier', dest='delaymod', type='float',
        metavar='FLOAT', default=1.0,
        help='Modify response delay (default: %default)')
    parser.add_option(
        '-b', '--server-pubkey', dest='serverpubkey', type='string',
        metavar='FILE', default='keys/id_rsa.pub',
        help='Use FILE as the server pubkey (default: %default)')
    parser.add_option(
        '-B', '--server-privkey', dest='serverprivkey', type='string',
        metavar='FILE', default='keys/id_rsa',
        help='Use FILE as the server privkey (default: %default)')
    opts, args = parser.parse_args()
    return (opts, args)


def viewer_option_parser():
    '''
    Default option parser for log viewer
    '''
    parser = optparse.OptionParser()
    parser.add_option(
        '-f', '--from-file', dest='inputfile', type='string',
        metavar='FILE', default=None,
        help='Read session capture from FILE instead of STDIN')
    parser.add_option(
        '-d', '--delay-modifier', dest='delaymod', type='float',
        metavar='FLOAT', default=1.0,
        help='Modify response delay (default: %default)')
    opts, args = parser.parse_args()
    return (opts, args)


PRINTABLE_FILTER = ''.join(
    [['.', chr(x)][chr(x) in string.printable[:-5]] for x in xrange(256)])


class Logger(object):
    '''
    logs telnet traffic to STDOUT/file (TAB-delimited)
    format: "time_since_start client/server 0xHex_data #plaintext"
    eg. "0.0572540760 server 0x0a0d55736572204e616d65203a20 #plaintext"
        "0.1084461212 client 0x6170630a #plaintext"
    '''
    def __init__(self):
        self.starttime = None
        self.logfile = None

    def open_log(self, filename):
        '''
        Set up a file for writing a log into it.
        If not called, log is written to STDOUT.
        '''
        self.logfile = open(filename, 'w')

    def close_log(self):
        '''
        Try to close a possibly open log file.
        '''
        if self.logfile is not None:
            self.logfile.close()
            self.logfile = None

    def log(self, who, what):
        '''
        Add a new message to log.
        '''
        # translate non-printable chars to dots
        plain = what.decode('hex').translate(PRINTABLE_FILTER)

        if self.starttime is None:
            self.starttime = time.time()

        timestamp = time.time() - self.starttime

        if self.logfile is not None:
            # write to a file
            self.logfile.write(
                "%0.10f\t%s\t0x%s\t#%s\n"
                % (timestamp, who, what, plain))
        else:
            # STDOUT output
            sys.stdout.write(
                "%0.10f\t%s\t0x%s\t#%s\n"
                % (timestamp, who, what, plain))


class ProxyProtocol(protocol.Protocol):
    '''
    Protocol class common to both client and server.
    '''
    def __init__(self):
        # all needed attributes are defined dynamically
        pass

    def proxy_data_received(self, data):
        '''
        Callback function for both client and server side of the proxy.
        Each side specifies its input (receive) and output (transmit) queues.
        '''
        if data is False:
            # Special value indicating that one side of our proxy
            # no longer has an open connection. So we close the
            # other end.
            self.receive = None
            self.transport.loseConnection()
            # the reactor should be stopping just about now
        elif self.transmit is not None:
            # Transmit queue is defined => connection to
            # the other side is still open, we can send data to it.
            self.transport.write(data)
            self.receive.get().addCallback(self.proxy_data_received)
        else:
            # got some data to be sent, but we no longer
            # have a connection to the other side
            sys.stderr.write(
                'Unable to send queued data: not connected to %s.\n'
                % (self.origin))
            # the other proxy instance should already be calling
            # reactor.stop(), so we can just take a nap

    def dataReceived(self, data):
        '''
        Received something from out input. Put it into the output queue.
        '''
        self.log.log(self.origin, data.encode('hex'))
        self.transmit.put(data)

    def connectionLost(self, reason=protocol.connectionDone):
        '''
        Either end of the proxy received a disconnect.
        '''
        if self.origin == 'server':
            sys.stderr.write('Disconnected from real server.\n')
        else:
            sys.stderr.write('Client disconnected.\n')
        self.log.close_log()
        # destroy the receive queue
        self.receive = None
        # put a special value into tx queue to indicate connecion loss
        self.transmit.put(False)
        # stop the program
        terminate()


class ProxyClient(ProxyProtocol):
    '''
    Client part of the MITM proxy
    '''
    def connectionMade(self):
        '''
        Successfully established a connection to the real server
        '''
        sys.stderr.write('Connected to real server.\n')
        self.origin = self.factory.origin
        # input - data from the real server
        self.receive = self.factory.serverq
        # output - data for the real client
        self.transmit = self.factory.clientq
        self.log = self.factory.log

        # callback for the receiver queue
        self.receive.get().addCallback(self.proxy_data_received)


class ProxyClientFactory(protocol.ClientFactory):
    '''
    Factory for proxy clients
    '''
    protocol = ProxyClient

    def __init__(self, serverq, clientq, log):
        # which side we're talking to?
        self.origin = 'server'
        self.serverq = serverq
        self.clientq = clientq
        self.log = log

    def clientConnectionFailed(self, connector, reason):
        self.clientq.put(False)
        sys.stderr.write('Unable to connect! %s\n' % reason.getErrorMessage())


class ProxyServer(ProxyProtocol):
    '''
    Server part of the MITM proxy
    '''
    # pylint: disable=R0201
    def connect_to_server(self):
        '''
        Example:
            factory = mitmproxy.ProxyClientFactory(
                self.transmit, self.receive, self.log)
            reactor.connect[PROTOCOL](
                self.host, self.port, factory [, OTHER_OPTIONS])
        '''
        raise MITMException('You should implement this method in your code.')
    # pylint: enable=R0201

    def connectionMade(self):
        '''
        Unsuspecting client connected to our fake server. *evil grin*
        '''
        # add callback for the receiver queue
        self.receive.get().addCallback(self.proxy_data_received)
        sys.stderr.write('Client connected.\n')
        # proxy server initialized, connect to real server
        sys.stderr.write(
            'Connecting to %s:%d...\n' % (self.host, self.port))
        self.connect_to_server()


class ProxyServerFactory(protocol.ServerFactory):
    '''
    Factory for proxy servers
    '''
    def __init__(self, proto, host, port, log):
        self.protocol = proto
        # which side we're talking to?
        self.protocol.origin = "client"
        self.protocol.host = host
        self.protocol.port = port
        self.protocol.log = log
        self.protocol.receive = defer.DeferredQueue()
        self.protocol.transmit = defer.DeferredQueue()


class ReplayServer(protocol.Protocol):
    '''
    Replay server class
    '''

    def __init__(self):
        pass

    def connectionMade(self):
        sys.stderr.write('Client connected.\n')
        self.send_next()

    def send_next(self):
        '''
        Called after the client connects.
        We shall send (with a delay) all the messages
        from our queue until encountering either None or
        an exception. In case a reply is not expected from
        us at this time, the head of queue will hold None
        (client is expected to send more messages before
        we're supposed to send a reply) - so we just "eat"
        the None from head of our queue (sq).
        '''
        while True:
            try:
                # gets either:
                #  * a message - continue while loop (send the message)
                #  * None - break from the loop (client talks next)
                #  * Empty exception - close the session
                reply = self.serverq.get(False)
                if reply is None:
                    break
            except Queue.Empty:
                # both cq and sq empty -> close the session
                assert self.serverq.empty()
                assert self.clientq.empty()
                sys.stderr.write('Success.\n')
                self.success = True
                self.log.close_log()
                self.transport.loseConnection()
                break

            (delay, what) = reply
            self.log.log('server', what)
            # sleep for a while (read from proxy log),
            # modified by delayMod
            time.sleep(delay * self.delaymod)
            self.transport.write(what.decode('hex'))

    def dataReceived(self, data):
        '''
        Called when client send us some data.
        Compare received data with expected message from
        the client message queue (cq), report mismatch (if any)
        try sending a reply (if available) by calling sendNext().
        '''
        try:
            expected = self.clientq.get(False)
        except Queue.Empty:
            raise MITMException("Nothing more expected in this session.")

        exp_hex = expected[1]
        got_hex = data.encode('hex')

        if got_hex == exp_hex:
            self.log.log('client', expected[1])
            self.send_next()
        else:
            # received something else, terminate
            sys.stderr.write(
                "ERROR: Expected %s (%s), got %s (%s).\n"
                % (exp_hex, exp_hex.decode('hex').translate(PRINTABLE_FILTER),
                    got_hex, got_hex.decode('hex').translate(PRINTABLE_FILTER)))
            self.log.close_log()
            terminate()

    def connectionLost(self, reason=protocol.connectionDone):
        '''
        Remote end closed the session.
        '''
        if not self.success:
            sys.stderr.write('FAIL! Premature end: not all messages sent.\n')
        sys.stderr.write('Client disconnected.\n')
        self.log.close_log()
        terminate()


class ReplayServerFactory(protocol.ServerFactory):
    '''
    Factory for replay servers
    '''
    protocol = ReplayServer

    def __init__(self, log, (serverq, clientq), delaymod, clientfirst):
        self.protocol.log = log
        self.protocol.serverq = serverq
        self.protocol.clientq = clientq
        self.protocol.delaymod = delaymod
        self.protocol.clientfirst = clientfirst
        self.protocol.success = False


def logreader(inputfile, serverq=Queue.Queue(), clientq=Queue.Queue(),
              clientfirst=None):
    '''
    Read the whole proxy log into two separate queues,
    one with the expected client messages (cq) and the
    other containing the replies that should be sent
    to the client.
    '''
    with open(inputfile) as infile:
        lasttime = 0
        for line in infile:
            # optional fourth field contains comments,
            # usually an ASCII representation of the data
            (timestamp, who, what, _) = line.rstrip('\n').split('\t')

            # if this is the first line of log, determine who said it
            if clientfirst is None:
                if who == "client":
                    clientfirst = True
                else:
                    clientfirst = False

            # strip the pretty-print "0x" prefix from hex data
            what = what[2:]
            # compute the time between current and previous msg
            delay = float(timestamp) - lasttime
            lasttime = float(timestamp)

            if who == 'server':
                # server reply queue
                serverq.put([delay, what])
            elif who == 'client':
                # put a sync mark into server reply queue
                # to distinguish between cases of:
                #  * reply consists of a single packet
                #  * more packets
                serverq.put(None)  # sync mark
                # expected client messages
                clientq.put([delay, what])
            else:
                raise MITMException('Malformed proxy log!')
    return (serverq, clientq, clientfirst)


def logviewer(inputfile, delaymod):
    '''
    Loads and simulates a given log file in either real-time
    or dilated by a factor of delayMod.
    '''
    with open(inputfile) as infile:
        lasttime = 0
        for line in infile:
            # optional fourth field contains comments,
            # usually an ASCII representation of the data
            (timestamp, who, what, _) = line.rstrip('\n').split('\t')
            # strip the pretty-print "0x" prefix from hex data
            what = what[2:]
            # strip telnet IAC sequences
            what = re.sub('[fF][fF]....', '', what)
            # compute the time between current and previous msg
            delay = float(timestamp) - lasttime
            lasttime = float(timestamp)

            # wait for it...
            time.sleep(delay * delaymod)

            if who == 'server':
                sys.stdout.write(what.decode('hex'))
                sys.stdout.flush()


#####################
# SSH related stuff #
#####################

# SSH proxy server

class SSHServerFactory(factory.SSHFactory):
    '''
    Factory class for proxy SSH server.

    If you want to implement your own logger of SSH Connection layer, subclass
    ProxySSHConnection and override log_channel_communication() method.
    Then set factory atribute after factory creation.
    Example:
        factory.connection = SubclassProxySSHConnection
    '''
    # ignore 'too-many-instance-attributes', 'too-many-arguments'
    # pylint: disable=R0902,R0913
    def __init__(
        self, proto, (host, port), log, showpass, (cpub, cpriv), (spub, spriv)):
        # Default is our ProxySSHConnection without logging implementation.
        self.connection = ProxySSHConnection
        self.origin = 'client'
        self.protocol = proto
        self.host = host
        self.port = port
        self.log = log
        self.serverq = defer.DeferredQueue()
        self.clientq = defer.DeferredQueue()
        self.cpub = cpub
        self.cpriv = cpriv
        self.spub = spub
        self.spriv = spriv
        self.showpass = showpass

        self.services = {
            'ssh-userauth':userauth.SSHUserAuthServer,
            'ssh-connection':self.connection,
        }

        self.portal = portal.Portal(Realm())
        self.portal.registerChecker(SSHCredentialsChecker(self))

    # pylint: enable=R0913

    def getPublicKeys(self):
        '''
        Provides public keys for proxy server.
        '''
        keypath = self.spub
        if not os.path.exists(keypath):
            raise MITMException(
                "Private/public keypair not generated in the keys directory.")

        return {'ssh-rsa': keys.Key.fromFile(keypath)}

    def getPrivateKeys(self):
        '''
        Provides private keys for proxy server.
        '''
        keypath = self.spriv
        if not os.path.exists(keypath):
            raise MITMException(
                "Private/public keypair not generated in the keys directory.")
        return {'ssh-rsa': keys.Key.fromFile(keypath)}

    # pylint: enable=R0902


class SSHServerTransport(transport.SSHServerTransport):
    '''
    SSH proxy server protocol. Subclass of SSH transport protocol layer
    representation for servers.
    '''
    # ignore 'too-many-public-methods'
    # pylint: disable=R0904
    def __init__(self):
        '''
        Nothing to do.
        '''
        pass

    def connectionMade(self):
        '''
        Calls parent method after establishing connection
        and sets some attributes.
        '''
        self.origin = self.factory.origin
        self.host = self.factory.host
        self.port = self.factory.port
        self.log = self.factory.log
        # input - data from the real client
        self.receive = self.factory.clientq
        # output - data for the real server
        self.transmit = self.factory.serverq

        transport.SSHServerTransport.connectionMade(self)

    def connectionLost(self, reason):
        '''
        Either end of the proxy received a disconnect.
        '''
        if self.origin == 'server':
            sys.stderr.write('Disconnected from real server.\n')
        else:
            sys.stderr.write('Client disconnected.\n')
        self.log.close_log()
        # destroy the receive queue
        self.receive = None
        # put a special value into tx queue to indicate connecion loss
        self.transmit.put(False)
        # stop the program
        terminate()

    def dispatchMessage(self, messageNum, payload):
        '''
        In parent method packets are distinguished and dispatched to message
        processing methods. Added extended logging.
        '''
        transport.SSHServerTransport.dispatchMessage(self, messageNum, payload)

    def sendPacket(self, messageType, payload):
        '''
        Extending internal logging and set message dispatching between proxy
        components if client successfully authenticated.
        '''
        transport.SSHServerTransport.sendPacket(self, messageType, payload)

        if messageType == 52:
            # SSH_MSG_USERAUTH_SUCCESS
            self.receive.get().addCallback(self.proxy_data_received)

    def proxy_data_received(self, data):
        '''
        Callback function for both client and server side of the proxy.
        Each side specifies its input (receive) and output (transmit) queues.
        '''
        if data is False:
            # Special value indicating that one side of our proxy
            # no longer has an open connection. So we close the
            # other end.
            self.receive = None
            self.transport.loseConnection()
            # the reactor should be stopping just about now
        elif self.transmit is not None:
            # Transmit queue is defined => connection to
            # the other side is still open, we can send data to it.
            self.sendPacket(ord(data[0]), data[1:])
            self.receive.get().addCallback(self.proxy_data_received)
        else:
            # got some data to be sent, but we no longer
            # have a connection to the other side
            sys.stderr.write(
                'Unable to send queued data: not connected to %s.\n'
                % (self.origin))
            # the other proxy instance should already be calling
            # reactor.stop(), so we can just take a nap

    # pylint: enable=R0904

class Realm(object):
    '''
    The realm connects application-specific objects to the authentication
    system.

    Realm connects our service and authentication methods.
    '''
    # ignore 'too-few-public-methods'
    # pylint: disable=R0903
    implements(portal.IRealm)

    def __init__(self, avatar=avatar.ConchUser):
        '''
        Set the default avatar object.
        '''
        self.avatar = avatar

    # ignore 'invalid-name', 'no-self-use'
    # pylint: disable=C0103,R0201
    def requestAvatar(self, avatarId, mind, *interfaces):
        '''
        Return object which provides one of the given interfaces of service.

        Our object provides no service interface and even won't be used, but
        this is needed for proper twisted ssh authentication mechanism.
        '''
        # ignore 'unused-argument' warning
        # pylint: disable=W0613
        return interfaces[0], self.avatar, lambda: None
        # pylint: enable=W0613

    # pylint: enable=C0103,R0201,R0903


class SSHCredentialsChecker(object):
    '''
    Implement publickey and password authentication method on proxy server
    side.
    '''
    implements(checkers.ICredentialsChecker)
    credentialInterfaces = (credentials.ISSHPrivateKey,
                            credentials.IUsernamePassword,)

    def __init__(self, my_factory):
        self.my_factory = my_factory
        self.receive = self.my_factory.clientq
        self.password = defer.DeferredQueue()
        # Need to know authentication method. Currently (publickey, password).
        self.method = None

    # ignore 'invalid-method-name'
    # pylint: disable=C0103
    # ignore 'nonstandard-exception'
    # pylint: disable=W0710
    def requestAvatarId(self, creds):
        '''
        Set a callback for user auth success
        '''
        if not hasattr(creds, "username"):
            raise python.failure.Failure(
                error.ConchError("Authentication Failed"))

        # set username for connect_to_server() method
        self.username = creds.username
        deferred = self.receive.get().addCallback(self.is_auth_success)

        if hasattr(creds, "password"):
            self.password.put(creds.password)
            if self.method == None:
                self.method = "password"
                self.connect_to_server()

        if self.method == None:
            self.method = "publickey"
            self.connect_to_server()

        return deferred

    # pylint: enable=C0103

    def is_auth_success(self, result):
        '''
        Check authentication result from proxy client.
        '''
        if result:
            return self.username
        else:
            # let proxy server know that it should disconnect client
            raise python.failure.Failure(
                error.ConchError("Authentication Failed"))

    # pylint: enable=W0710

    def connect_to_server(self):
        '''
        Start mitm proxy client.
        '''
        # now connect to the real server and begin proxying...
        client_factory = SSHClientFactory(SSHClientTransport,
                                          (self.my_factory.serverq,
                                          self.my_factory.clientq),
                                          self.my_factory.log,
                                          (self.username,
                                          self.password,
                                          self.my_factory.showpass),
                                          (self.my_factory.cpub,
                                          self.my_factory.cpriv))
        client_factory.connection = self.my_factory.connection
        client_factory.method = self.method
        reactor.connectTCP(self.my_factory.host, self.my_factory.port,
                           client_factory)


# SSH proxy client.

# ignore 'too-many-instance-attributes'
# pylint: disable=R0902
class SSHClientFactory(protocol.ClientFactory):
    '''
    Factory class for proxy SSH client.
    '''
    def __init__(self, proto, (serverq, clientq), log,
                 (username, password, showpass), (cpub, cpriv)):
        # which side we're talking to?
        self.origin = 'server'
        self.protocol = proto
        self.serverq = serverq
        self.clientq = clientq
        self.log = log
        self.username = username
        self.password = password
        self.method = "publickey"
        self.showpass = showpass
        self.cpub = cpub
        self.cpriv = cpriv

        # NOTE: In the future we can let user define how to log conn layer
        self.connection = ProxySSHConnection

    def clientConnectionFailed(self, connector, reason):
        self.clientq.put(False)
        sys.stderr.write('Unable to connect! %s\n' % reason.getErrorMessage())


# ignore 'too-many-public-methods'
# pylint: disable=R0904,R0902

class SSHClientTransport(transport.SSHClientTransport):
    '''
    SSH proxy client protocol. Subclass of SSH transport protocol layer
    representation for clients.
    '''
    def __init__(self):
        '''
        Nothing to do
        '''
        pass

    def connectionMade(self):
        '''
        Call parent method after enstablishing connection and make some
        initialization.
        '''
        self.connection = self.factory.connection
        self.username = self.factory.username
        self.password = self.factory.password
        self.showpass = self.factory.showpass
        self.client_first_method = self.factory.method
        self.origin = self.factory.origin
        # input - data from the real server
        self.receive = self.factory.serverq
        # output - data for the real client
        self.transmit = self.factory.clientq
        self.log = self.factory.log

        # callback for the receiver queue
        self.receive.get().addCallback(self.proxy_data_received)

        transport.SSHClientTransport.connectionMade(self)
        sys.stderr.write('Connected to real server.\n')

    def connectionLost(self, reason):
        '''
        Either end of the proxy received a disconnect.
        '''
        if self.origin == 'server':
            sys.stderr.write('Disconnected from real server.\n')
        else:
            sys.stderr.write('Client disconnected.\n')
        self.log.close_log()
        # destroy the receive queue
        self.receive = None
        # put a special value into tx queue to indicate connecion loss
        self.transmit.put(False)
        # stop the program
        terminate()

    def dispatchMessage(self, messageNum, payload):
        '''
        Add internal logging of incoming packets.
        '''
        transport.SSHClientTransport.dispatchMessage(self, messageNum, payload)

    def sendPacket(self, messageType, payload):
        '''
        Add internal logging of outgoing packets.
        '''
        transport.SSHClientTransport.sendPacket(self, messageType, payload)

    def verifyHostKey(self, pubKey, fingerprint):
        '''
        Required implementation of server host key verification.
        As we're acting as a passthrogh, we can safely leave this
        up to the client.
        '''
        # ignore 'unused-argument' warning
        # pylint: disable=W0613
        return defer.succeed(1)
        # pylint: enable=W0613

    def connectionSecure(self):
        '''
        Required implementation of a call to run another service.
        '''
        self.requestService(
            ProxySSHUserAuthClient(
                self.username, self.connection()))

    def proxy_data_received(self, data):
        '''
        Callback function for both client and server side of the proxy.
        Each side specifies its input (receive) and output (transmit) queues.
        '''
        if data is False:
            # Special value indicating that one side of our proxy
            # no longer has an open connection. So we close the
            # other end.
            self.receive = None
            self.transport.loseConnection()
            # the reactor should be stopping just about now
        elif self.transmit is not None:
            # Transmit queue is defined => connection to
            # the other side is still open, we can send data to it.
            self.sendPacket(ord(data[0]), data[1:])
            self.receive.get().addCallback(self.proxy_data_received)
        else:
            # got some data to be sent, but we no longer
            # have a connection to the other side
            sys.stderr.write(
                'Unable to send queued data: not connected to %s.\n'
                % (self.origin))
            # the other proxy instance should already be calling
            # reactor.stop(), so we can just take a nap

# pylint: enable=R0904


class ProxySSHUserAuthClient(userauth.SSHUserAuthClient):
    '''
    Implements client side of 'ssh-userauth'.
    '''
    def __init__(self, user, instance):
        '''
        Call parent constructor.
        '''
        userauth.SSHUserAuthClient.__init__(self, user, instance)

    def ssh_USERAUTH_FAILURE(self, packet):
        '''
        Let the proxy server know about auth-method failure.
        Fix bug in parent class' method.
        '''
        if self.lastAuth is not "none":
            # Send info about failure to proxy server, and it depends on method
            # kind and order on client side.
            if (self.lastAuth is not "publickey"
                    or self.transport.client_first_method is not "password"):
                self.transport.transmit.put(False)

        from twisted.conch.ssh.common import getNS
        _, partial = getNS(packet)
        partial = ord(partial)
        # if partial: <<< so nasty BUG!!!
        if not partial: # fix
            self.authenticatedWith.append(self.lastAuth)

        return userauth.SSHUserAuthClient.ssh_USERAUTH_FAILURE(self, packet)

    def ssh_USERAUTH_SUCCESS(self, packet):
        '''
        Let the proxy server know about auth-method success and call parent
        method.
        '''
        self.transport.transmit.put(True)
        return userauth.SSHUserAuthClient.ssh_USERAUTH_SUCCESS(self, packet)

    def show_password(self, password):
        '''
        Show password on proxy output if option was true.
        '''
        if self.transport.showpass:
            sys.stderr.write("SSH 'password' is: '%s'" % password)

        return password


    def getPassword(self, prompt = None):
        '''
        Return deffered with password from ssh proxy server and add callback
        for showing password.
        '''
        tmp_deferred = self.transport.password.get()
        tmp_deferred.addCallback(self.show_password)
        return tmp_deferred

    def getPublicKey(self):
        '''
        Create PublicKey blob and return it or raise exception.
        '''
        keypath = self.transport.factory.cpub
        if not (os.path.exists(keypath)):
            raise MITMException(
                "Public/private keypair not generated in the keys directory.")
        return keys.Key.fromFile(keypath).blob()

    def getPrivateKey(self):
        '''
        Create PrivateKey object and return it or raise exception.
        '''
        keypath = self.transport.factory.cpriv
        if not (os.path.exists(keypath)):
            raise MITMException(
                "Public/private keypair not generated in the keys directory.")
        return defer.succeed(keys.Key.fromFile(keypath).keyObject)


# common to both SSH server and client
# ignore 'too-many-public-methods'
# pylint: disable=R0904

class ProxySSHConnection(connection.SSHConnection):
    '''
    Overrides regular SSH connection protocol layer.

    Dispatches packets between proxy componets (server/client part) instead of
    message processing and performs channel communication logging.
    '''
    def packetReceived(self, messageNum, packet):
        '''
        Log data and send received packet to the proxy server side.
        '''
        self.log_channel_communication(chr(messageNum) + packet)
        self.transport.transmit.put(chr(messageNum) + packet)

    def log_channel_communication(self, payload):
        '''
        Logs channel communication.

        @param payload: The payload of the message at SSH connection layer.
        @type payload: C{str}
        '''
        # NOTE: does not distinguish channels,
        #       could be a problem if multiple channels are used
        #       (the problem: channel numbers are assigned "randomly")

        # match SSH_MSG_CHANNEL_DATA messages
        if ord(payload[0]) == 94:
            # Payload:
            # byte      SSH_MSG_CHANNEL_DATA (94)
            # uint32    recipient channel
            # string    data    (string = uint32 + string)

            # ssh message type
            msg = payload[0:1]

            # "pseudo-randomly" assigned channel number,
            # (almost) always 0x00000000 for shell
            channel = payload[1:5]

            # length of shell channel data in bytes,
            # undefined for other channel types
            datalen = payload[5:9]

            # channel data
            data = payload[9:]

            #sys.stderr.write("packet: %s %s %s %s\n"
            #    % (msg.encode('hex'), channel.encode('hex'),
            #    datalen.encode('hex'), data.encode('hex')))

            self.transport.log.log(self.transport.origin, data.encode('hex'))

# pylint: enable=R0904


class SSHFactory(factory.SSHFactory):
    '''
    Base factory class for mitmproxy ssh servers. Create and set your
    authentication checker or subclass.

    @ivar spub: A path to server public key.
    @type spub: C{str}
    @ivar spriv: A path to server private key.
    @type spriv: C{str}
    '''
    def __init__(self, opts):
        '''
        SSHFactory construcotr.

        @param opts: Class with atributes opts.logfile, opts.serverpubkey,
        opts.serverprivkey
        '''
        self.log = Logger()
        if opts.logfile is not None:
            self.log.open_log(opts.logfile)

        self.spub = opts.serverpubkey
        self.spriv = opts.serverprivkey
        self.portal = portal.Portal(Realm())

    def set_authentication_checker(self, checker):
        '''
        Set portal's credentials checker.
        '''
        self.portal.checkers = {}
        self.portal.registerChecker(checker)

    def getPublicKeys(self):
        '''
        Provide public keys for proxy server.
        '''
        keypath = self.spub
        if not os.path.exists(keypath):
            raise MITMException(
                "Private/public keypair not generated in the keys directory.")

        return {'ssh-rsa': keys.Key.fromFile(keypath)}

    def getPrivateKeys(self):
        '''
        Provide private keys for proxy server.
        '''
        keypath = self.spriv
        if not os.path.exists(keypath):
            raise MITMException(
                "Private/public keypair not generated in the keys directory.")
        return {'ssh-rsa': keys.Key.fromFile(keypath)}


class SSHReplayCredentialsChecker(object):
    '''
    Allow access on reply server with publickey or password authentication
    method.
    '''
    # ignore 'too-few-public-methods'
    # pylint: disable=R0903
    implements(checkers.ICredentialsChecker)
    credentialInterfaces = (credentials.ISSHPrivateKey,
                            credentials.IUsernamePassword,)
    def __init__(self):
        '''
        Nothing to do.
        '''
        pass

    # pylint: disable=C0103,W0613,R0201
    def requestAvatarId(self, creds):
        '''
        Return avatar id for any authentication method.
        '''
        return "ANONYMOUS"

    # pylint: enable=C0103,R0903,R0201,W0613


class SSHReplayServerFactory(SSHFactory):
    '''
    Factory class for SSH replay server.
    '''
    def __init__(self, opts):
        '''
        Initialize base class and SSHReplayServerFactory.
        '''
        SSHFactory.__init__(self, opts)

        (serverq, clientq, clientfirst) = logreader(opts.inputfile)
        self.serverq = serverq
        self.clientq = clientq
        self.clientfirst = clientfirst
        self.delaymod = opts.delaymod
        self.origin = "client"
        self.success = False

        self.portal = portal.Portal(Realm(ReplayAvatar(self)))
        self.portal.registerChecker(SSHReplayCredentialsChecker())
        self.protocol = SSHReplayServer


# pylint: disable=R0904
class SSHReplayServer(transport.SSHServerTransport):
    '''
    Provides SSH replay server service.
    '''
    def __init__(self):
        '''
        Nothing to do. Parent class doesn't have constructor.
        '''
        pass

    def connectionMade(self):
        '''
        Print info on stderr and call parent method after
        establishing connection.
        '''
        return transport.SSHServerTransport.connectionMade(self)

    def dispatchMessage(self, messageNum, payload):
        '''
        Added extended logging.
        '''
        return transport.SSHServerTransport.dispatchMessage(self, messageNum,
                                                            payload)

    def sendPacket(self, messageType, payload):
        '''
        Added extended logging.
        '''

        return transport.SSHServerTransport.sendPacket(self, messageType,
                                                       payload)
# pylint: enable=R0904


class ReplayAvatar(avatar.ConchUser):
    '''
    SSH replay service spawning shell
    '''
    implements(interfaces.ISession)

    def __init__(self, replayfactory):
        self.factory = replayfactory
        avatar.ConchUser.__init__(self)
        self.username = 'nobody'
        self.channelLookup.update({'session':session.SSHSession})
    def openShell(self, protocol):
        server_factory = ReplayServerFactory(
            self.factory.log, (self.factory.serverq, self.factory.clientq),
            self.factory.delaymod, self.factory.clientfirst)
        server_factory.protocol = SSHReplayServerProtocol
        server_factory.protocol = server_factory.protocol()
        server_factory.protocol.makeConnection(protocol)
        protocol.makeConnection(session.wrapProtocol(server_factory.protocol))
    def getPty(self, terminal, windowSize, attrs):
        return None
    def execCommand(self, protocol, cmd):
        raise NotImplementedError
    def windowChanged(self, newWindowSize):
        pass
    def eofReceived(self):
        pass
    def closed(self):
        '''
        Stop reactor after SSH session is closed.
        '''
        terminate()

class SSHReplayServerProtocol(ReplayServer):
    '''
    Override ReplayServer protocol, because we can't stop reactor before client
    sends all messages.
    '''
    def __init__(self):
        ReplayServer.__init__(self)

    def connectionLost(self, reason=protocol.connectionDone):
        '''
        Don't terminate reactor like in parent method. It will be terminated
        at ssh layer.
        '''
        if not self.success:
            sys.stderr.write('FAIL! Premature end: not all messages sent.\n')
        sys.stderr.write('Client disconnected.\n')
        self.log.close_log()

