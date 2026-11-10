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

## Fragment reassembly

These tests use the default four-pbuf reassembly budget. Build and run them from
the repository root:

```sh
make static
cc -O2 -Isrc/include -Isrc/ports/include tests/ip4_protocol.c bin/liblwip.a -o bin/ip4-protocol-test
cc -O2 -Isrc/include -Isrc/ports/include tests/ip6_empty.c bin/liblwip.a -o bin/ip6-empty-test
bin/ip4-protocol-test
bin/ip6-empty-test 4
bin/ip6-empty-test 5
```

The IPv4 test checks every arrival order of interleaved UDP and ICMP fragments
with matching addresses and identification, plus a different-ID control. It
also verifies that the reassembly budget can evict an unrelated protocol's
datagram with the same addresses and ID.

The IPv6 test rejects a first fragment whose pbuf chain exceeds the budget and
checks timeout cleanup with an independent allocation counter. It also covers
early rejection, duplicates, overlaps, rejected continuations, out-of-order
completion and reinitialization.

For GCC or Clang, enable incoming checksum checks and sanitizers in both the
library and test executables, using separate build directories:

```sh
CC=cc
FLAGS='-O1 -g -Itests/checked -fsanitize=address,undefined -fno-omit-frame-pointer'
make static CC="$CC" PP="$CC -E" CFLAGS="$FLAGS" BUILDDIR=build/reassembly BINDIR=bin/reassembly
for test in ip4_protocol ip6_empty; do
  "$CC" $FLAGS -Isrc/include -Isrc/ports/include "tests/$test.c" bin/reassembly/liblwip.a -o "bin/reassembly/$test"
done
export ASAN_OPTIONS=detect_leaks=1
export UBSAN_OPTIONS=halt_on_error=1
bin/reassembly/ip4_protocol
bin/reassembly/ip6_empty 4
bin/reassembly/ip6_empty 5
```

The IPv6 regression also checks budget exhaustion with eviction disabled. Using
the same compiler and flags as above:

```sh
FLAGS="$FLAGS -DIP_REASS_FREE_OLDEST=0"
make static CC="$CC" PP="$CC -E" CFLAGS="$FLAGS" BUILDDIR=build/reassembly-no-evict BINDIR=bin/reassembly-no-evict
"$CC" $FLAGS -Isrc/include -Isrc/ports/include tests/ip6_empty.c bin/reassembly-no-evict/liblwip.a -o bin/reassembly-no-evict/ip6_empty
bin/reassembly-no-evict/ip6_empty 4
bin/reassembly-no-evict/ip6_empty 5
```
