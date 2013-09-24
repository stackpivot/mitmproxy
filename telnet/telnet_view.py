#!/usr/bin/env python2.7
'''
View a log file with an optional time dilation.
See --help for usage.
'''

from optparse import OptionParser
import sys
import time
import re


def main():
    parser = OptionParser()
    parser.add_option('-f', '--from-file', dest='inputFile', type='string',
                      metavar='FILE', default=None,
                      help='Read session capture from FILE instead of STDIN')
    parser.add_option('-d', '--delay-modifier', dest='delayMod', type='float',
                      metavar='FLOAT', default=1.0,
                      help='Modify response delay (default: 1.0 - no change)')
    (opts, args) = parser.parse_args()

    if opts.inputFile is None:
        print "Need to specify an input file."
        sys.exit(1)
    else:
        with open(opts.inputFile) as inFile:
            lastTime = 0
            for line in inFile:
                # optional fourth field contains comments,
                # usually an ASCII representation of the data
                (timestamp, who, what, _) = line.rstrip('\n').split('\t')
                # strip the pretty-print "0x" prefix from hex data
                what = what[2:]
                # strip telnet IAC sequences
                what = re.sub('[fF][fF]....', '', what)
                # compute the time between current and previous msg
                delay = float(timestamp) - lastTime
                lastTime = float(timestamp)

                # wait for it...
                time.sleep(delay * opts.delayMod)

                if who == 'server':
                    sys.stdout.write(what.decode('hex'))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
