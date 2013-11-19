#!/usr/bin/env python2.7
'''
Replay server for SSH.
See --help for usage.
'''

from twisted.internet import reactor
import sys

sys.path.append('../lib')
import mitmproxy


def main():
    '''
    parse options, open and read log file, start replay server
    '''
    (opts, _) = mitmproxy.ssh_replay_option_parser(2222)

    if opts.inputfile is None:
        sys.stderr.write('Need to specify an input file.\n')
        sys.exit(1)

    sys.stderr.write(
        'Server running on localhost:%d\n' % opts.localport)

    factory = mitmproxy.ReplaySSHServerFactory(opts)
    reactor.listenTCP(opts.localport, factory)
    reactor.run()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
