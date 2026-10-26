# Native regressions

Run the transparent UDP netif-binding regression with the repository's default
configuration:

```sh
make static
cc -O2 -Isrc/include -Isrc/ports/include tests/udp_netif.c bin/liblwip.a -o bin/udp-netif-test
bin/udp-netif-test
```

It injects IPv4 and IPv6 packets from the same client endpoint into two netifs.
Each interface must accept one peer and receive only its four datagrams.
It uses in-memory packets and requires no sockets, TUN devices or routing changes.
