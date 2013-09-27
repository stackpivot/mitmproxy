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
    '''
    logs telnet traffic to STDOUT/file (TAB-delimited)
    format: "time_since_start client/server 0xHex_data"
    eg. "0.0572540760 server 0x0a0d55736572204e616d65203a20 #plaintext"
        "0.1084461212 client 0x6170630a #plaintext"
    '''

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
        plain = what.decode('hex').translate(filter)

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


class TelnetServer(protocol.Protocol):
    def connectionMade(self):
        self.log = self.factory.log
        self.sq = self.factory.sq
        self.cq = self.factory.cq
        self.delayMod = self.factory.delayMod
        self.success = False

        sys.stderr.write('Client connected.\n')

    def sendNext(self):
        '''
        Called after we've received data from the client.
        We shall send (with a delay) all the messages
        from our queue until encountering either None or
        an exception. In case a reply is not expected from
        us at this time, the head of queue will hold None
        (client is expected to send more messages before
        we're supposed to send a reply) - so we just "eat"
        the None from head of our queue (sq).
        '''
        try:
            reply = self.sq.get(False)
        except:
            # expect the unexpected
            raise

        while reply is not None:
            (delay, what) = reply
            self.log.log('server', what)
            # sleep for a while (read from proxy log),
            # modified by delayMod
            time.sleep(delay * self.delayMod)
            self.transport.write(what.decode('hex'))
            try:
                # gets either:
                #  * a message - continue while loop (send the message)
                #  * None - break from the loop (client talks next)
                #  * Empty exception - close the session
                reply = self.sq.get(False)
            except Queue.Empty:
                # both cq and sq empty -> close the session
                sys.stderr.write('Success.\n')
                self.success = True
                self.log.closeLog()
                self.transport.loseConnection()
                break
            except:
                # no idea what just happened
                raise

    def dataReceived(self, data):
        '''
        Called when client send us some data.
        Compare received data with expected message from
        the client message queue (cq), report mismatch (if any)
        try sending a reply (if available) by calling sendNext().
        '''
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
        '''
        Remote end closed the session.
        '''
        if not self.success:
            sys.stderr.write('FAIL! Premature end: not all messages sent.\n')
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

        # Read the whole proxy log into two separate queues,
        # one with the expected client messages (cq) and the
        # other containing the replies that should be sent
        # to the client.
        with open(opts.inputFile) as inFile:
            lastTime = 0
            for line in inFile:
                # optional fourth field contains comments,
                # usually an ASCII representation of the data
                (timestamp, who, what, _) = line.rstrip('\n').split('\t')
                # strip the pretty-print "0x" prefix from hex data
                what = what[2:]
                # compute the time between current and previous msg
                delay = float(timestamp) - lastTime
                lastTime = float(timestamp)

                if who == 'server':
                    # server reply queue
                    sq.put([delay, what])
                elif who == 'client':
                    # put a sync mark into server reply queue
                    # to distinguish between cases of:
                    #  * reply consists of a single packet
                    #  * more packets
                    sq.put(None)  # sync mark
                    # expected client messages
                    cq.put([delay, what])
                else:
                    raise Exception('Malformed proxy log!')

        # get rid of first sync mark (client ALWAYS talks first)
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
