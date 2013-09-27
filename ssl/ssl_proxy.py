#!/usr/bin/env python2.7
'''
SSL interceptor and logger.
See --help for usage.
'''

from twisted.internet import protocol, reactor, defer, ssl
import sys

sys.path.append('../lib')
import mitmproxy


class ProxyServer(mitmproxy.ProxyServer):
    def connectToServer(self):
        factory = mitmproxy.ProxyClientFactory(
            self.factory.sq, self.factory.cq, self.log)
        reactor.connectSSL(
            self.host, self.port, factory, ssl.ClientContextFactory())


def main():
    parsed = mitmproxy.ProxyOptionParser(443, 4443)

    log = mitmproxy.Logger()
    if parsed.opts.logFile is not None:
        log.openLog(parsed.opts.logFile)

    sys.stderr.write('Server running on localhost:%d...\n'
        % parsed.opts.localPort)

    factory = mitmproxy.ProxyServerFactory(
        ProxyServer, parsed.opts.host, parsed.opts.port, log)
    reactor.listenSSL(
        parsed.opts.localPort, factory, ssl.DefaultOpenSSLContextFactory(
            'keys/server.key', 'keys/server.crt'))
    reactor.run()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
