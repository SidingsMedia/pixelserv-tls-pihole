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
<!--
## Install on Entware

Binary packages are distributed by Entware. Beta version binaries during development are distributed from this GitHub repository.

#### Pre-built binaries
````
opkg install pixelserv-tls
````

## Install on Arch Linux

A package is available from Arch User Repository (AUR). This [package](https://aur.archlinux.org/packages/pixelserv-tls/) works on all Arch Linux derived distributions such as Manjaro, Antergos and Chakra.

#### Pre-built binaries using `yay`
````
yay -S pixelserv-tls
````

#### Build from source package
````
git clone https://aur.archlinux.org/pixelserv-tls.git
cd pixelserv-tls
makepkg -si
````

## Install on EdgeRouter X

See this [installation guide](https://kazoo.ga/run-pixelserv-tls-on-erx/). Or simply:

#### Pre-built binary
````
sudo -i
cd /tmp
curl -O https://raw.githubusercontent.com/kvic-z/goodies-edgemax/master/pixelserv-tls_2.2.1-1_mipsel.deb
dpkg -i pixelserv-tls_2.2.1-1_mipsel.deb
````
The binary is built for and tested on EdgeOS v1.x. It's not tested on EdgeOS v2.x and most likely it won't be compatible.

## Install on Homebrew (macOS) and Linuxbrew

```
brew install https://kazoo.ga/pixelserv-tls/pixelserv-tls.rb
```

## Install as a Docker container

See https://hub.docker.com/r/imthai/pixelserv-tls

## Install on Raspberry Pi

Binary packages are available from this [Github](https://github.com/jumpsmm7/). Should work on all Raspberry Pi's running Raspbian (Debian 10). For installation issues, you may refer to this [tracker](https://github.com/kvic-z/pixelserv-tls/issues/32).

#### Pre-built binary
````
sudo -i
cd /tmp
curl -O https://raw.githubusercontent.com/jumpsmm7/pixelserv-tls_2.3.1-1_armhf.deb/master/pixelserv-tls_2.3.1-1_armhf.deb
dpkg -i pixelserv-tls_2.3.1-1_armhf.deb
````
and follow the on-screen instructions.
-->
## Launch pixelserv-tls
````
pixelserv-tls <listening ip>
````

Check out the [man page](https://github.com/kvic-z/pixelserv-tls/wiki/Command-Line-Options) for customization and command line options.

