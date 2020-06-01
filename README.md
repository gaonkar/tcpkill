# tcpkill with SYN
Modified [original tcpkill](http://monkey.org/~dugsong/dsniff/) to close tcp connection that might not have any data
flowing to it. The blog [https://blog.cloudflare.com/when-tcp-sockets-refuse-to-die/](https://blog.cloudflare.com/when-tcp-sockets-refuse-to-die/)
has a discussion about open sockets where the clients have closed the connection. If we want to send a RST, we need to obtain the sequence number.
 To do that, we send a spoofed SYN packet and wait for the acknowlegement. This modification has been added to the original program.

Note that this program will continue to send RST to any new connection to that particular source port. It need to be
killed

# TO DO

Add the ability to read the /proc/tcp and process those connections only

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


