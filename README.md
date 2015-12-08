slwhttp [![Build Status](http://bit.ly/1LWfQzT)](http://bit.ly/1NBOLTN)
=======

This project is designed to be an extremely lightweight file dumping daemon
based on a limited HTTP/1.0 protocol implementation that only supports "GET"
requests.  A major emphasis was placed on security and path sandboxing during
the development of this application, which should be easily verifiable due to
the lack of bloat in contrast with other HTTP daemons (such as Apache or nginx).

Compliation & Installation
==========================

Simply install `g++ autoconf automake libtool make` if on a Debian based OS, or
similar packages for your system.  Then, type `sh autogen.sh` to generate the
configuration script and Makefiles.  After that, run `./configure` and
`make install` to install the binary.

Usage
=====

Run `slwhttp --help` for usage information.

Contributing
============

Before submitting a pull request, consider opening an issue first so that your
contribution can be discussed in detail before working on it.

License
=======

For licensing information, please see `LICENSE` in the project's root directory.
