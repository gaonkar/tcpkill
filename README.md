# tcpkill with SYN
Modified [original tcpkill](http://monkey.org/~dugsong/dsniff/) to close tcp connection that might not have any data
flowing to it. The blog [https://blog.cloudflare.com/when-tcp-sockets-refuse-to-die/](https://blog.cloudflare.com/when-tcp-sockets-refuse-to-die/)
has a discussion about open sockets where the clients have closed the connection. If we want to send a RST, we need to obtain the sequence number.
 To do that, we send a spoofed SYN packet and wait for the acknowlegement. This modification has been added to the original program.

There is a perl based script [killcx](http://killcx.sourceforge.net).

# Usage
```
Usage: tcpkill [-i interface] [-m max kills] [-r num_rst_packets]
        -s      source ip address
        -d      destination ip address
        -p      source port
        -q      destination port
```

# Test

Added a test script in python. Running
```
sudo make test
```
should allow one to test the working of this program



Modified tcpkill


tcpkill
        kills specified in-progress TCP connections (useful for
        libnids-based applications which require a full TCP 3-whs for
        TCB creation).
