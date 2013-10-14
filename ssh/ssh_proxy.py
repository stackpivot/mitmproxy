#!/usr/bin/env python2.7
'''
SSH interceptor and logger.
See --help for usage.
'''

from twisted.internet import reactor
import sys

sys.path.append('../lib')
import mitmproxy

def main():
    (opts, _) = mitmproxy.proxy_option_parser(22, 2222)

    log = mitmproxy.Logger()
    if opts.logfile is not None:
        log.open_log(opts.logfile)

    sys.stderr.write(
        'Server running on localhost:%d...\n' % (opts.localport))

    factory = mitmproxy.SSHServerFactory(mitmproxy.SSHServerTransport,
                                         opts.host, opts.port,
                                         log)
    reactor.listenTCP(opts.localport, factory)
    reactor.run()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)

