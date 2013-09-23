#!/usr/bin/env python2.7
'''
Replay server for telnet (or any other protocol running over port 23).
See --help for usage.

Assumptions:
  * client ALWAYS talks first (sends option negotiation requests)
'''

from twisted.internet import protocol, reactor
from optparse import OptionParser
import Queue
import sys
import string
import time

filter = ''.join(
    [['.', chr(x)][chr(x) in string.printable[:-5]] for x in xrange(256)])


class Logger():
    """
    logs telnet traffic to STDOUT/file (TAB-delimited)
    format: "time_since_start client/server 0xHex_data"
    eg. "0.0572540760 server 0x0a0d55736572204e616d65203a20 #plaintext"
        "0.1084461212 client 0x6170630a #plaintext"
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


class TelnetServer(protocol.Protocol):
    def connectionMade(self):
        self.log = self.factory.log
        self.sq = self.factory.sq
        self.cq = self.factory.cq
        self.delayMod = self.factory.delayMod

        sys.stderr.write('Client connected.\n')

    def sendNext(self):
        try:
            reply = self.sq.get(False)
        except:
            raise

        while reply is not None:
            self.log.log('server', reply[1])
            (delay, what) = reply
            time.sleep(delay * self.delayMod)
            self.transport.write(what.decode('hex'))
            try:
                reply = self.sq.get(False)
            except Queue.Empty:
                sys.stderr.write('The End.\n')
                self.log.closeLog()
                self.transport.loseConnection()
                break

    def dataReceived(self, data):
        try:
            expected = self.cq.get(False)
        except Queue.Empty:
            raise Exception("Nothing more expected in this session.")

        exp_hex = expected[1]
        got_hex = data.encode('hex')

        if got_hex == exp_hex:
            self.log.log('client', expected[1])
            self.sendNext()
        else:
            sys.stderr.write(
                "ERROR: Expected %s, got %s.\n"
                % (exp_hex, got_hex))

    def connectionLost(self, reason):
        sys.stderr.write('Client disconnected.\n')
        self.log.closeLog()
        reactor.stop()


class TelnetServerFactory(protocol.ServerFactory):
    protocol = TelnetServer

    def __init__(self, log, sq, cq, delayMod):
        self.log = log
        self.sq = sq
        self.cq = cq
        self.delayMod = delayMod


def main():
    parser = OptionParser()
    parser.add_option('-p', '--local-port', dest='localPort', type='int',
                      metavar='PORT', default=2323,
                      help='Local port to listen on')
    parser.add_option('-f', '--from-file', dest='inputFile', type='string',
                      metavar='FILE', default=None,
                      help='Read session capture from FILE instead of STDIN')
    parser.add_option('-o', '--output', dest='logFile', type='string',
                      metavar='FILE', default=None,
                      help='Log into FILE instead of STDOUT')
    parser.add_option('-d', '--delay-modifier', dest='delayMod', type='float',
                      metavar='FLOAT', default=1.0,
                      help='Modify response delay (default: 1.0 - no change)')
    (opts, args) = parser.parse_args()

    if opts.inputFile is None:
        print "Need to specify an input file."
        sys.exit(1)
    else:
        log = Logger()
        if opts.logFile is not None:
            log.openLog(opts.logFile)

        sq = Queue.Queue()
        cq = Queue.Queue()

        with open(opts.inputFile) as inFile:
            lastTime = 0
            for line in inFile:
                (timestamp, who, what, _) = line.rstrip('\n').split('\t')
                what = what[2:]
                delay = float(timestamp) - lastTime
                lastTime = float(timestamp)
                if who == 'server':
                    sq.put([delay, what])
                elif who == 'client':
                    sq.put(None)  # sync mark
                    cq.put([delay, what])
                else:
                    raise Exception('WTF?!')

        # get rid of first sync mark (client talks first)
        sq.get(False)

        sys.stderr.write('Server running on localhost:%d\n' % opts.localPort)
        factory = TelnetServerFactory(log, sq, cq, opts.delayMod)
        reactor.listenTCP(opts.localPort, factory)
        reactor.run()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
