#!/usr/bin/env python2.7
'''
View a log file with an optional time dilation.
See --help for usage.
'''

import sys

sys.path.append('./lib')
import mitmproxy


def main():
    parsed = mitmproxy.ViewerOptionParser()

    if parsed.opts.inputFile is None:
        print "Need to specify an input file."
        sys.exit(1)
    else:
        mitmproxy.LogViewer(parsed.opts.inputFile, parsed.opts.delayMod)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
