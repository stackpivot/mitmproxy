#!/usr/bin/env python2
'''
SSL interceptor and logger.
See --help for usage.
'''

from twisted.internet import reactor, ssl
import sys
import os

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
        Connect over SSL-encrypted raw socket
        '''
        factory = mitmproxy.ProxyClientFactory(
            self.transmit, self.receive, self.log)
        reactor.connectSSL(
            self.host, self.port, factory, ssl.ClientContextFactory())


def main():
    '''
    Parse options, open log and start proxy server
    '''
    (opts, _) = mitmproxy.proxy_option_parser(443, 4443)

    if not os.path.exists('keys/server.key') \
    or not os.path.exists('keys/server.crt'):
        print "Please do create server certificates."
        sys.exit(1)

    log = mitmproxy.Logger()
    if opts.logfile is not None:
        log.open_log(opts.logfile)

    sys.stderr.write(
        'Server running on localhost:%d...\n' % opts.localport)

    factory = mitmproxy.ProxyServerFactory(
        ProxyServer, opts.host, opts.port, log)
    reactor.listenSSL(
        opts.localport, factory, ssl.DefaultOpenSSLContextFactory(
            'keys/server.key', 'keys/server.crt'))
    reactor.run()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
