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

## Creating a service

In order to get pixelsrv-tls to run constantly on Linux you will need to create a service. An example of a service file can be found below. This has been tested on 
Debian 10. You may need to modify it to suit your distribution.

````
Filename: pixelsrv-tls.service
````
````
[Unit]
Description=A tiny bespoke webserver for adblock with HTTP/1.1 and HTTPS support
After=network.target

[Service]
ExecStart=/usr/local/bin/pixelserv-tls 192.168.1.2 -p 8080 -l 1 -z /var/cache/pixelserv -f
Restart=always

[Install]
WantedBy=multi-user.target
````
After creating this file in `/etc/systemd/system` or whereever your service files are stored, you will be able to start and stop your pixelsrv-tls server like any other 
service with commands like `systemctl start pixelsrv-tls.service` or `systemctl stop pixelsrv-tls.service`.
