#!/usr/bin/env python2.7
'''
HTTP interceptor and logger.
See --help for usage.

Assumptions:
* no http redirects
* relative links, not absolute

Solution to both of the above problems:
* run http_replay.py as root with local port set to 80 (real server's port)
* override DNS resolution for the original domain to localhost (via /etc/hosts)
'''

from twisted.internet import reactor
import sys

sys.path.append('../lib')
import mitmproxy


class ProxyServer(mitmproxy.ProxyServer):
    def connectToServer(self):
        factory = mitmproxy.ProxyClientFactory(
            self.tx, self.rx, self.log)
        reactor.connectTCP(
            self.host, self.port, factory)


def main():
    parsed = mitmproxy.ProxyOptionParser(80, 8080)

    log = mitmproxy.Logger()
    if parsed.opts.logFile is not None:
        log.openLog(parsed.opts.logFile)

    sys.stderr.write(
        'Server running on localhost:%d...\n' % parsed.opts.localPort)

    factory = mitmproxy.ProxyServerFactory(
        ProxyServer, parsed.opts.host, parsed.opts.port, log)
    reactor.listenTCP(parsed.opts.localPort, factory)
    reactor.run()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
