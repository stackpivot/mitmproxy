HTTP INTERCEPTOR
================

See --help for usage.


NOTES
-----
* best to run it as

  ```
  while true; do proxy_http.py [options]; done
  ```

  * that's because the proxy terminates after each connection close, which might be OK for some limited amount of tools, but completely unusable with full-blown browsers and such

* support for relative links, not absolute
  * when the real client sees absolute link, it creates a new, direct connection to the real server (can be overriden via /etc/hosts for local clients; DNS spoofing otherwise)
  * the above also fixes the `Host` HTTP header
  * however, make sure you're using IP address as an argument to -H option when going the /etc/hosts way! (infinite recursion FTW!)

* must bind to port 80 (or whatever the real server is running at) to be compatible with redirects and absolute/relative links
  * either run proxy as root (dirty and insecure) or use authbind / iptables / selinux
