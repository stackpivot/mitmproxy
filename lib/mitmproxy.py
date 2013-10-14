#!/usr/bin/env python2.7
'''
Common MITM proxy classes.
'''

from twisted.internet import protocol, reactor, defer

# Twisted imports for SSH.
from twisted.conch.ssh import connection, factory, keys, session, transport, \
                              userauth
from twisted.cred import checkers, credentials, portal
from twisted.conch import avatar, error
from zope.interface import implements

# python.log
from twisted import python

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
        help='Hostname/IP of real server')
    parser.add_option(
        '-P', '--port', dest='port', type='int',
        metavar='PORT', default=port,
        help='Port of real server')
    parser.add_option(
        '-p', '--local-port', dest='localport', type='int',
        metavar='PORT', default=localport,
        help='Local port to listen on')
    parser.add_option(
        '-o', '--output', dest='logfile', type='string',
        metavar='FILE', default=None,
        help='Save log to FILE instead of writing to stdout')
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
        help='Local port to listen on')
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
        help='Modify response delay (default: 1.0 - no change)')
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
        help='Modify response delay (default: 1.0 - no change)')
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
        Each side specifies its input (rx) and output (tx) queues.
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


def logreader(inputfile, serverq, clientq, clientfirst):
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


#####################
# SSH related stuff #
#####################

# SSH proxy server

class SSHServerFactory(factory.SSHFactory):
    '''
    Factory class for proxy SSH server.

    If you want to implement your own logger of SSH Connection layer, subclass
    ProxySSHConnection and override logChannelCommunication() method.
    Then set factory atribute after factory creation.
    Example:
        factory.connection = SubclassProxySSHConnection
    '''
    def __init__(self, protocol, host, port, log):
        # Default is our ProxySSHConnection without logging implementation.
        self.connection = ProxySSHConnection
        self.origin = 'client'
        self.protocol = protocol
        self.host = host
        self.port = port
        self.log = log
        self.serverq = defer.DeferredQueue()
        self.clientq = defer.DeferredQueue()

        if not (os.path.exists('keys/id_rsa.pub')
                and os.path.exists('keys/id_rsa')):
            raise MITMException(
                "Private/public eypair not generated in the keys directory.")

        self.privateKeys = {
            'ssh-rsa': keys.Key.fromFile('keys/id_rsa')
        }
        self.publicKeys = {
            'ssh-rsa': keys.Key.fromFile('keys/id_rsa.pub')
        }

        self.services = {
            'ssh-userauth':userauth.SSHUserAuthServer,
            'ssh-connection':self.connection,
        }

        self.portal = portal.Portal(Realm())
        self.portal.registerChecker(PublicKeyCredentialsChecker(self))



class SSHServerTransport(transport.SSHServerTransport):
    '''
    SSH proxy server protocol. Subclass of SSH transport protocol layer
    representation for servers.
    '''
    # TODO: This class has only slight difference from client ssh transport
    # protocol layer. This subclass is better createid with some factory method.
    def connectionMade(self):
        '''
        Calls parent method after establishing connection
        and sets some attributes.
        '''
        self.origin = self.factory.origin
        self.host = self.factory.host
        self.port = self.factory.port
        self.log = self.factory.log
        # input - data from the real server XXX: really?
        self.receive = self.factory.clientq
        # output - data for the real client XXX: really?
        self.transmit = self.factory.serverq

        transport.SSHServerTransport.connectionMade(self)
        sys.stderr.write('Client connected.\n')

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

        python.log.msg("Received message (%s) from %s with payload: %s " % (
            messageNum, self.origin, payload.encode('string_escape')))

    def sendPacket(self, messageType, payload):
        '''
        Extending internal logging and set message dispatching between proxy
        components if client successfully authenticated.
        '''
        transport.SSHServerTransport.sendPacket(self, messageType, payload)

        python.log.msg("Sent message (%s) to %s with payload: %s " % (
            messageType, self.origin, payload.encode('string_escape')))

        if messageType == 52:
            # SSH_MSG_USERAUTH_SUCCESS
            self.receive.get().addCallback(self._cbProxyDataReceived)

    def _cbProxyDataReceived(self, data):
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
            self.receive.get().addCallback(self._cbProxyDataReceived)
        else:
            # got some data to be sent, but we no longer
            # have a connection to the other side
            sys.stderr.write(
                'Unable to send queued data: not connected to %s.\n'
                % (self.origin))
            # the other proxy instance should already be calling
            # reactor.stop(), so we can just take a nap


class Realm(object):
    '''
    The realm connects application-specific objects to the authentication
    system.

    Realm connects our service and authentication methods.
    '''
    # NOTE: This class will be useless, if we subclass porta.Portal.
    implements(portal.IRealm)

    def requestAvatar(self, avatarId, mind, *interfaces):
        return interfaces[0], EavesdroppedUser(avatarId), lambda: None


class EavesdroppedUser(avatar.ConchUser):
    # NOTE: This class will be useless, if we subclass porta.Portal.
    def __init__(self, username):
        avatar.ConchUser.__init__(self)

        self.username = username


class PublicKeyCredentialsChecker:
    '''
    Implements one of several client authentication on proxy server side.
    '''
    implements(checkers.ICredentialsChecker)
    credentialInterfaces = (credentials.ISSHPrivateKey,)

    def __init__(self, factory):
        self.host = factory.host
        self.port = factory.port
        self.serverq = factory.serverq
        self.clientq = factory.clientq
        self.log = factory.log
        self.connection = factory.connection
        self.receive = self.clientq

    def requestAvatarId(self, credentials):
        '''
        Set a callback for user auth success
        '''
        d = self.receive.get().addCallback(self._cbIsAuthSuccess,
                credentials.username)
        self.connectToServer(credentials.username)

        return d

    def _cbIsAuthSuccess(self, result, avatarId):
        '''
        Check authentication result from proxy client.
        '''
        if result:
            return avatarId
        else:
            # let proxy server know that it should disconnect client
            raise python.failure.Failure(
                error.ConchError("Authorization Failed"))

    def connectToServer(self, username):
        '''
        Start mitm proxy client.
        '''
        sys.stderr.write(
            'Connecting to %s:%d...\n' % (self.host, self.port))

        # now connect to the real server and begin proxying...
        factory = SSHClientFactory(SSHClientTransport, self.serverq,
                                   self.clientq, self.log, username)
        factory.connection = self.connection
        reactor.connectTCP(self.host, self.port, factory)


# SSH proxy client.

class SSHClientFactory(protocol.ClientFactory):
    '''
    Factory class for proxy SSH client.
    '''
    # TODO: Change this. We can use normal client factory for TCP.

    def __init__(self, protocol, serverq, clientq, log, username):
        # which side we're talking to?
        self.origin = 'server'
        self.protocol = protocol
        self.serverq = serverq
        self.clientq = clientq
        self.log = log
        self.username = username

        # NOTE: In the future we can let a user define how to log connection
        # layer
        self.connection = ProxySSHConnection

    def clientConnectionFailed(self, connector, reason):
        self.clientq.put(False)
        sys.stderr.write('Unable to connect! %s\n' % reason.getErrorMessage())


class SSHClientTransport(transport.SSHClientTransport):
    '''
    SSH proxy client protocol. Subclass of SSH transport protocol layer
    representation for clients.
    '''
    # TODO: This class has only slight difference from server ssh transport
    # protocol layer. This subclass is better created by some factory
    # method.
    def connectionMade(self):
        '''
        Call parent method fter enstablishing connection and set some
        attributes and callback.
        '''
        self.connection = self.factory.connection
        self.username = self.factory.username
        self.origin = self.factory.origin
        # input - data from the real server XXX: really?
        self.receive = self.factory.serverq
        # output - data for the real client XXX: really?
        self.transmit = self.factory.clientq
        self.log = self.factory.log

        # callback for the receiver queue
        self.receive.get().addCallback(self._cbProxyDataReceived)

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
        In parent method packets are distinguished and dispatched to message
        processing methods. Added logging and checking original client against
        proxy server.
        '''
        transport.SSHClientTransport.dispatchMessage(self, messageNum, payload)

        python.log.msg("Received message (%s) from %s with payload: %s " % (
            messageNum, self.origin, payload.encode('string_escape')))

        # We'll let the proxy server know about auth success
        if messageNum == 52:
            # SSH_MSG_USERAUTH_SUCCESS
            self.transmit.put(True)

    def sendPacket(self, messageType, payload):
        '''
        Subclassed for extending internal logging.
        '''
        transport.SSHClientTransport.sendPacket(self, messageType, payload)

        python.log.msg("Sent message (%s) to %s with payload: %s " % (
            messageType, self.origin, payload.encode('string_escape')))

    def verifyHostKey(self, pubKey, fingerprint):
        '''
        Required implementation of server host key verification.
        As we're acting as a passthrogh, we can safely leave this
        up to the client.
        '''
        return defer.succeed(1)

    def connectionSecure(self):
        '''
        Required implementation of a call to run another service.
        '''
        self.requestService(ProxySSHUserAuthClient(self.username,
                                                   self.connection()))

    def _cbProxyDataReceived(self, data):
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
            self.receive.get().addCallback(self._cbProxyDataReceived)
        else:
            # got some data to be sent, but we no longer
            # have a connection to the other side
            sys.stderr.write(
                'Unable to send queued data: not connected to %s.\n'
                % (self.origin))
            # the other proxy instance should already be calling
            # reactor.stop(), so we can just take a nap



class ProxySSHUserAuthClient(userauth.SSHUserAuthClient):
    def getPassword(self, prompt = None):
        # we won't do password authentication XXX: why?
        # TODO: implement me maybe?
        return

    def getPublicKey(self):
        if not (os.path.exists('keys/id_rsa.pub')):
            raise MITMException(
                "Public/private keypair not generated in the keys directory.")
        return keys.Key.fromFile('keys/id_rsa.pub').blob()

    def getPrivateKey(self):
        if not (os.path.exists('keys/id_rsa')):
            raise MITMException(
                "Public/private keypair not generated in the keys directory.")
        return defer.succeed(keys.Key.fromFile('keys/id_rsa').keyObject)


# common to both SSH server and client

class ProxySSHConnection(connection.SSHConnection):
    '''
    Overrides regular SSH connection protocol layer.

    Dispatches packets between proxy componets (server/client part) instead of
    message processing and performs channel communication logging.
    '''
    def packetReceived(self, messageNum, packet):
        self.logChannelCommunication(chr(messageNum) + packet)
        self.transport.transmit.put(chr(messageNum) + packet)

    def logChannelCommunication(self, payload):
        '''
        Logs channel communication.

        @param payload: The payload of the message at SSH connection layer.
        @type payload: C{str}
        '''
        if ord(payload[0]) == 94:
            # SSH_MSG_CHANNEL_DATA
            self.transport.log.log(self.transport.origin, payload.encode('hex'))

