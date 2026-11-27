# Native regressions

Run all in-memory regressions on a native Unix build (no network privileges needed):

```sh
make -j4 check
```

`frag_output` sends chained UDP buffers through an in-memory netif. It checks
the final fragment's length and flags, the driver's error at the UDP caller,
and that fragmentation does not consume the caller's buffer chain. `tcp_gso`
checks both a working GSO device and one that returns `ERR_MEM` for offload:
wire-sized fallback packets must carry the same bytes without a GSO tag.
`reass_netif` checks that IPv4/IPv6 fragment timeout replies use the original
input interface even when a different interface is the default route.
`tcp_gso_rexmit` covers partially ACKed retransmissions during software fallback,
including sequence-number wrap, FIN and final send-buffer/callback accounting.
`ip6_limits` checks the full-packet 16-bit size boundary before and after fragment
reassembly, with extension headers and both arrival orders. `frag_duplicate`
checks that rejected duplicates/overlaps cannot evict another interface's data
when the fragment budget is full.

Run the transparent UDP netif-binding regression with the repository's default
configuration:

```sh
make static
cc -O2 -Isrc/include -Isrc/ports/include tests/udp_netif.c bin/liblwip.a -o bin/udp-netif-test
bin/udp-netif-test
```

It injects IPv4 and IPv6 packets from the same client endpoint into two netifs.
Each interface must accept one peer and receive only its four datagrams.
It also rejects the first peer on each interface by removing the new PCB;
input must return after one notification and later packets must still work.
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
datagram with the same addresses and ID, or the same protocol on another netif.
Removing one netif must leave the other netif's pending datagrams intact.

The IPv6 test rejects a first fragment whose pbuf chain exceeds the budget and
checks timeout cleanup with an independent allocation counter. It also covers
early rejection, duplicates, overlaps, rejected continuations, out-of-order
completion, interface removal, and reinitialization. A fragment that cannot
fit even an empty budget must not evict an unrelated datagram.

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
