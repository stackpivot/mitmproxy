HTTP interceptor and logger
===========================

See --help for usage.


Limitations
-----------
* support for relative links, not absolute
  * when the real client sees absolute link, it creates a new, direct connection to the real server (can be overriden via /etc/hosts for local clients; DNS spoofing otherwise)
* must bind to port 80 (or whatever the real server is running at) to be compatible with redirects and absolute/relative links
  * either run proxy as root (dirty and insecure) or use authbind / iptables / selinux
