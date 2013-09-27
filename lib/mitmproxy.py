#!/usr/bin/env python2.7
'''
Common MITM proxy classes.
'''

from twisted.internet import protocol, reactor, defer
import optparse
import time
import sys
import string


class ProxyOptionParser():
    def __init__(self, port, localPort):
        self.parser = optparse.OptionParser()
        self.parser.add_option(
            '-H', '--host', dest='host', type='string',
            metavar='HOST', default='localhost',
            help='Hostname/IP of physical fencing device')
        self.parser.add_option(
            '-P', '--port', dest='port', type='int',
            metavar='PORT', default=port,
            help='Port of physical fencing device')
        self.parser.add_option(
            '-p', '--local-port', dest='localPort', type='int',
            metavar='PORT', default=localPort,
            help='Local port to listen on')
        self.parser.add_option(
            '-o', '--output', dest='logFile', type='string',
            metavar='FILE', default=None,
            help='Save log to FILE instead of writing to stdout')
        self.opts, self.args = self.parser.parse_args()


class Logger():
    '''
    logs telnet traffic to STDOUT/file (TAB-delimited)
    format: "time_since_start client/server 0xHex_data"
    eg. "0.0572540760 server 0x0a0d55736572204e616d65203a20 #plaintext"
        "0.1084461212 client 0x6170630a #plaintext"
    '''

    filter = ''.join(
        [['.', chr(x)][chr(x) in string.printable[:-5]] for x in xrange(256)])

    def __init__(self):
        self._startTime = None
        self._logFile = None

    def openLog(self, filename):
        '''
        Set up a file for writing a log into it.
        If not called, log is written to STDOUT.
        '''
        try:
            self._logFile = open(filename, 'w')
        except:
            raise

    def closeLog(self):
        '''
        Try to close a possibly open log file.
        '''
        if self._logFile is not None:
            try:
                self._logFile.close()
                self._logFile = None
            except:
                raise

    def log(self, who, what):
        '''
        Add a new message to log.
        '''
        # translate non-printable chars to dots
        plain = what.decode('hex').translate(self.filter)

        if self._startTime is None:
            self._startTime = time.time()

        timestamp = time.time() - self._startTime

        if self._logFile is not None:
            # write to a file
            self._logFile.write(
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
    def proxyDataReceived(self, data):
        '''
        Callback function for both client and server side of the proxy.
        Each side specifies its input (rx) and output (tx) queues.
        '''
        if data is False:
            # Special value indicating that one side of our proxy
            # no longer has an open connection. So we close the
            # other end.
            self.rx = None
            self.transport.loseConnection()
            # the reactor should be stopping just about now
        elif self.tx is not None:
            # Transmit queue is defined => connection to
            # the other side is still open, we can send data to it.
            self.transport.write(data)
            self.rx.get().addCallback(self.proxyDataReceived)
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
        self.tx.put(data)

    def connectionLost(self, reason):
        '''
        Either end of the proxy received a dosconnect.
        '''
        if self.origin == 'server':
            sys.stderr.write('Disconnected from physical fence device.\n')
        else:
            sys.stderr.write('Client disconnected.\n')
        self.log.closeLog()
        # destroy the receive queue
        self.rx = None
        # put a special value into tx queue to indicate connecion loss
        self.tx.put(False)
        # stop the program
        if reactor.running:
            reactor.stop()


class ProxyClient(ProxyProtocol):
    def connectionMade(self):
        '''
        Successfully established a connection to the real server.
        '''
        sys.stderr.write('Connected to physical fence device.\n')
        self.origin = self.factory.origin
        # input - data from the real server
        self.rx = self.factory.sq
        # output - data for the real client
        self.tx = self.factory.cq
        self.log = self.factory.log

        # callback for the receiver queue
        self.rx.get().addCallback(self.proxyDataReceived)


class ProxyClientFactory(protocol.ClientFactory):
    protocol = ProxyClient

    def __init__(self, sq, cq, log):
        # which side we're talking to?
        self.origin = 'server'
        self.sq = sq
        self.cq = cq
        self.log = log


class ProxyServer(ProxyProtocol):
    '''
    Server part of the MITM proxy.
    '''
    def connectionMade(self):
        '''
        Unsuspecting client connected to our fake server. *evil grin*
        '''
        self.origin = self.factory.origin
        self.host = self.factory.host
        self.port = self.factory.port
        self.log = self.factory.log
        # input - data from the real client
        self.rx = self.factory.cq
        # output - data to the real server
        self.tx = self.factory.sq

        # callback for the receiver queue
        self.rx.get().addCallback(self.proxyDataReceived)

        sys.stderr.write('Client connected.\n')
        sys.stderr.write(
            'Connecting to %s:%d...\n' % (self.host, self.port))

        # now connect to the real server and begin proxying...
        self.connectToServer()


class ProxyServerFactory(protocol.ServerFactory):
    def __init__(self, protocol, host, port, log):
        self.protocol = protocol
        # which side we're talking to?
        self.origin = "client"
        self.host = host
        self.port = port
        self.log = log
        self.sq = defer.DeferredQueue()
        self.cq = defer.DeferredQueue()
