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

# disable reporting of bogus "no-member" errors
# pylint: disable=E1101


class ProxyServer(mitmproxy.ProxyServer):
    '''
    ProxyServer with implemented connect procedure
    '''
    def connect_to_server(self):
        '''
        Connect over raw TCP
        '''
        factory = mitmproxy.ProxyClientFactory(
            self.transmit, self.receive, self.log)
        reactor.connectTCP(
            self.host, self.port, factory)


def main():
    '''
    Parse options, open log and start proxy server
    '''
    (opts, _) = mitmproxy.proxy_option_parser(80, 8080)

    log = mitmproxy.Logger()
    if opts.logfile is not None:
        log.open_log(opts.logfile)

    sys.stderr.write(
        'Server running on localhost:%d...\n' % opts.localport)

    factory = mitmproxy.ProxyServerFactory(
        ProxyServer, opts.host, opts.port, log)
    reactor.listenTCP(opts.localport, factory)
    reactor.run()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
