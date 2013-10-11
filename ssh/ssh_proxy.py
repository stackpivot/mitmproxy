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
    parsed = mitmproxy.ProxyOptionParser(22, 2222)

    log = mitmproxy.Logger()
    if parsed.opts.logFile is not None:
        log.openLog(parsed.opts.logFile)

    sys.stderr.write(
        'Server running on localhost:%d...\n' % (parsed.opts.localPort))

    factory = mitmproxy.SSHServerFactory(mitmproxy.SSHServerTransport,
                                         parsed.opts.host, parsed.opts.port,
                                         log)
    reactor.listenTCP(parsed.opts.localPort, factory)
    reactor.run()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)

