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
`sudo make install` to install the binary (`sudo` required for setuid bit).

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

Performance
===========

The following log from ApacheBench has been altered for readability.  Metrics
were not changed.

<pre>
root@test:~/htdocs# ab -n 1024 -c 128 http://localhost/10M.test
This is ApacheBench, Version 2.3 <$Revision: 1638069 $>
Copyright 1996 Adam Twiss, Zeus Technology Ltd, http://www.zeustech.net/
Licensed to The Apache Software Foundation, http://www.apache.org/

Concurrency Level:      128
Time taken for tests:   3.132 seconds
Complete requests:      1024
Bytes transferred:      10 Mbytes
Requests per second:    326.91 [#/sec] (mean)
Time per request:       391.544 [ms] (mean)
Time per request:       3.059 [ms] (mean, across all concurrent requests)
Transfer rate:          25.54 [Gbits/sec] received

Connection Times (ms)
              min  mean[+/-sd] median   max
Connect:        0    1   2.7      0      10
Processing:    31  377 290.6    304    1186
Waiting:        0    1   1.4      0       8
Total:         31  378 292.0    304    1186

Percentage of the requests served within a certain time (ms)
50%     304
75%     553
90%     843
95%     979
98%    1021
99%    1078
100%   1186 (longest request)
</pre>
