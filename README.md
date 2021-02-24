[![Build Status](https://travis-ci.org/kvic-z/pixelserv-tls.svg?branch=master)](https://travis-ci.org/kvic-z/pixelserv-tls)


_pixelserv-tls_ is a tiny bespoke HTTP/1.1 webserver with HTTPS and SNI support. It acts on behalf of hundreds of thousands of advert/tracker servers and responds to all requests with  nothing  to  speed  up  web browsing.

_pixelserv-tls_  supports TLSv1.0, TLSv1.2 and TLSv1.3 and thus could operate with a wide range of browsers and client devices.  Server  certificates  for any  given  advert/tracker domains are generated automatically on first use and saved to disk.

pixelserv-tls can log access and HTTP/1.1 POST contents to syslog. So it  is  also  a  useful  tool  to  inspect and expose 'wrongly blocked' domains as well as 'rogue' domains invading user privacy.

This fork of pixelserv-tls redirects all HTTPS traffic to HTTP which means that the Pi-Hole blocking page can be used instead of a blank screen.

## Build from source

This works on all Linux distributions and Linux-like environments such Homebrew for macOS and Cygwin for Windows.

````
autoreconf -i
./configure
make install
````

## Launch pixelserv-tls
````
pixelserv-tls <listening ip>
````

Check out the [man page](https://github.com/kvic-z/pixelserv-tls/wiki/Command-Line-Options) for customization and command line options.

