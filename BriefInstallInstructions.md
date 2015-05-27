# Introduction #

You'll need to grab Wireshark sources, throw spdyshark in the plugins directory, modify makefiles using spdyshark\_build.patch, run autogen.sh, configure, and then make.


# Details #

Download and extract the Wireshark 1.7.1 sources:

```
$ wget http://www.wireshark.org/download/src/wireshark-1.7.1.tar.bz2
$ tar jxvf wireshark-1.7.1.tar.bz2
```

Download the latest spdyshark sources, placing the spdyshark subdirectory inside wireshark-1.7.1/plugins.
```
$ git clone https://code.google.com/p/spdyshark/
$ cp -r spdyshark/spdyshark wireshark-1.7.1/plugins/
```

Patch the Wireshark build files:

```
$ cd wireshark-1.7.1
$ patch -p1 < ../spdyshark/spdyshark_build.patch
$ ./autogen.sh
```

Configure, build and install as usual:

```
$ ./configure --with-ssl && make install
```