#!/usr/bin/env python2.7
'''
Telnet (or any other protocol running over port 23) interceptor and logger.
See --help for usage.
'''

from twisted.internet import protocol, reactor, defer
from optparse import OptionParser
import time
import sys
import string

filter = ''.join(
    [['.', chr(x)][chr(x) in string.printable[:-5]] for x in xrange(256)])


class Logger():
    """
    logs telnet traffic to STDOUT/file (TAB-delimited)
    format: "time_since_start client/server 0xHex_data"
    eg. "0.0572540760 server 0x0a0d55736572204e616d65203a20"
        "0.1084461212 client 0x6170630a"
    """

    def __init__(self):
        self._startTime = None
        self._logFile = None

    def openLog(self, filename):
        try:
            self._logFile = open(filename, 'w')
        except:
            raise

    def closeLog(self):
        if self._logFile is not None:
            try:
                self._logFile.close()
                self._logFile = None
            except:
                raise

    def log(self, who, what):
        # translate non-printable chars to dots
        plain = what.decode('hex').translate(filter)
        if self._startTime is None:
            self._startTime = time.time()

        timestamp = time.time() - self._startTime

        if self._logFile is not None:
            self._logFile.write(
                "%0.10f\t%s\t0x%s\t#%s\n"
                % (timestamp, who, what, plain))
        else:
            sys.stdout.write(
                "%0.10f\t%s\t0x%s\t#%s\n"
                % (timestamp, who, what, plain))


class TelnetProxyClient(protocol.Protocol):
    def connectionMade(self):
        sys.stderr.write('Connected to physical fence device.\n')
        self.sq = self.factory.sq
        self.cq = self.factory.cq
        self.log = self.factory.log

        self.cq.get().addCallback(self.serverDataReceived)

    def serverDataReceived(self, data):
        if data is False:
            self.cq = None
            self.transport.loseConnection()
        elif self.cq:
            self.log.log("client", data.encode('hex'))
            self.transport.write(data)
            self.cq.get().addCallback(self.serverDataReceived)
        else:
            self.factory.cq.put(data)

    def dataReceived(self, data):
        self.log.log("server", data.encode('hex'))
        self.factory.sq.put(data)

    def connectionLost(self, reason):
        if self.cq:
            sys.stderr.write('Disconnected from physical fence device.\n')
            self.log.closeLog()
            self.cq = None
            try:
                reactor.stop()
            except:
                pass


class TelnetProxyClientFactory(protocol.ClientFactory):
    protocol = TelnetProxyClient

    def __init__(self, sq, cq, log):
        self.sq = sq
        self.cq = cq
        self.log = log


class TelnetProxyServer(protocol.Protocol):
    def connectionMade(self):
        self.host = self.factory.host
        self.port = self.factory.port
        self.log = self.factory.log
        self.sq = self.factory.sq
        self.cq = self.factory.cq

        self.sq.get().addCallback(self.clientDataReceived)

        sys.stderr.write('Client connected.\n')
        sys.stderr.write('Connecting to %s:%d...\n' % (self.host, self.port))

        factory = TelnetProxyClientFactory(self.sq, self.cq, self.log)
        reactor.connectTCP(self.host, self.port, factory)

    def clientDataReceived(self, data):
        self.transport.write(data)
        self.sq.get().addCallback(self.clientDataReceived)

    def dataReceived(self, data):
        self.cq.put(data)

    def connectionLost(self, reason):
        sys.stderr.write('Client disconnected.\n')
        self.cq.put(False)
        self.log.closeLog()
        try:
            reactor.stop()
        except:
            pass


class TelnetProxyServerFactory(protocol.ServerFactory):
    protocol = TelnetProxyServer

    def __init__(self, host, port, log):
        self.host = host
        self.port = port
        self.log = log
        self.sq = defer.DeferredQueue()
        self.cq = defer.DeferredQueue()


def main():
    parser = OptionParser()
    parser.add_option('-H', '--host', dest='host', type='string',
                      metavar='HOST', default='localhost',
                      help='Hostname/IP of physical fencing device')
    parser.add_option('-P', '--port', dest='port', type='int',
                      metavar='PORT', default=23,
                      help='Port of physical fencing device')
    parser.add_option('-p', '--local-port', dest='localPort', type='int',
                      metavar='PORT', default=2323,
                      help='Local port to listen on')
    parser.add_option('-o', '--output', dest='logFile', type='string',
                      metavar='FILE', default=None,
                      help='Save log to FILE instead of writing to stdout')
    (opts, args) = parser.parse_args()

    log = Logger()
    if opts.logFile is not None:
        log.openLog(opts.logFile)

    sys.stderr.write('Server running on localhost:%d...\n' % opts.localPort)
    factory = TelnetProxyServerFactory(opts.host, opts.port, log)
    reactor.listenTCP(opts.localPort, factory)
    reactor.run()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
