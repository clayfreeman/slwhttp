slwhttp [![Build Status](http://bit.ly/1LWfQzT)](http://bit.ly/1NBOLTN)
=======

This project is designed to be an extremely lightweight file dumping daemon
based on a limited HTTP/1.0 protocol implementation that only supports "GET"
requests.  A major emphasis was placed on security and path sandboxing during
the development of this application, which should be easily verifiable due to
the lack of bloat in contrast with other HTTP daemons (such as Apache or nginx).

Compliation & Installation
==========================

Simply install `build-essential` if on a Debian based OS, or a similar package
for your system.  Then, type `make` to compile.  After compilation, set the
appropriate permissions for the executable and move it to a `PATH` directory as
shown below:

```bash
chown root:root slwhttp
chmod 4755 slwhttp
mv slwhttp /usr/local/bin
```

Usage
=====

Run `slwhttp --help` for usage information.
