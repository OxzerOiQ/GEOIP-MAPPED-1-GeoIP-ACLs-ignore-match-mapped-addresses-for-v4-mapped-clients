**Affected product:** ISC BIND 9 (`named`) — ACL evaluation / GeoIP (GeoIP2)  
**Affected code:** `lib/dns/acl.c:139-144`, `lib/dns/acl.c:176`, `lib/dns/acl.c:384-388`  
**Severity:** Low (config-dependent, deterministic)  
**Status:** Reported to ISC  

---

## Table of contents

- [Summary](#summary)
- [Affected versions](#affected-versions)
- [Preconditions](#preconditions)
- [Impact](#impact)
- [Screenshots / proof](#screenshots--proof)
- [Steps to reproduce](#steps-to-reproduce)
- [Current vs expected behavior](#current-vs-expected-behavior)
- [Suggested fix](#suggested-fix)
- [Disclosure timeline](#disclosure-timeline)

---

## Summary

`dns_acl_match()` applies the `match-mapped-addresses` conversion only to the
radix/prefix search (`lib/dns/acl.c:139-144`); the non-radix element loop
(`acl.c:176`) passes the **raw** request address to `dns_aclelement_match()`.
Because MaxMind databases store IPv4 data under the `::ffff:0:0/96` subtree of
their IPv6 tree, `MMDB_lookup_sockaddr()` resolves a v4-mapped IPv6 address
(`::ffff:a.b.c.d`) to the same record as plain IPv4 (verified against a
production GeoLite2 database).

Result: with the **default** `match-mapped-addresses no`, a client arriving in
v4-mapped form does **not** match IPv4 prefix elements (documented, intended)
but **does** match `geoip` elements — so
`allow-query { !10.53.0.2; geoip country US; }` **allows** a US client at
10.53.0.2 when its address arrives v4-mapped, while refusing the identical
client as plain IPv4. Demonstrated live using a PROXY v2 listener.

## Affected versions

- Tested: BIND 9.21.26-dev (development branch, built from source) with
  GeoIP2 support enabled.
- Likely affected: all supported branches with GeoIP2 — the ACL conversion
  code is long-standing. I did not re-run on stable releases.

```
BIND 9.21.26-dev (Development Release) <id:9.21.26-dev-test>
running on Linux x86_64 6.6.87.2-microsoft-standard-WSL2 (Ubuntu 24.04.1 LTS)
built by meson with -Dgeoip=enabled
compiled by GCC 13.3.0
compiled with OpenSSL version: OpenSSL 3.0.13 30 Jan 2024
compiled with libuv version: 1.48.0
libmaxminddb 1.9.1
```

## Preconditions

1. `named` built with GeoIP2 (`-Dgeoip=enabled`, libmaxminddb) and at least
   one `geoip` ACL element in use (`match-clients`, `allow-query`,
   `allow-recursion`, etc.).
2. `match-mapped-addresses no` (the **default**; `bin/include/defaultconfig.h:46`).
3. A path delivering v4-mapped client addresses. `named`'s own listeners force
   `IPV6_V6ONLY` (`lib/isc/netmgr/udp.c:155`, `tcp.c:326`), so directly
   connected clients never arrive mapped; the open path is **PROXY v2**: an
   `AF_INET6` PROXY header's 16 address bytes are accepted verbatim
   (`lib/isc/proxy2.c:399-426`), only all-zero addresses are rejected
   (`lib/isc/netmgr/netmgr.c:2333`), and the header address becomes the ACL
   peer (`proxystream.c:190`, `proxyudp.c:242`). Dual-stack frontends
   (dnsdist / haproxy / envoy class) commonly emit `::ffff:` source addresses
   for IPv4 clients terminating on non-`V6ONLY` sockets.
4. Per the ARM Security Assumptions, operators reasonably expect
   `match-mapped-addresses no` to uniformly prevent v4-mapped clients from
   matching IPv4 address rules; GeoIP elements silently exempt themselves.

## Impact

- **Negated-prefix bypass (demonstrated live):** an ACL of the form
  `{ !<network>; geoip country <X>; }` admits clients from the excluded
  network when their addresses arrive v4-mapped; the same clients are refused
  as plain IPv4.
- **View-selection inconsistency:** in GeoIP-segmented multi-view setups,
  identical clients can land in different views purely by address encoding.
- Not a DoS, no memory-safety impact.

## Screenshots / proof

 ++
 

## Steps to reproduce

1. Build `named` with `-Dgeoip=enabled`.
2. Copy the in-tree fixture databases:
   `cp bin/tests/system/geoip2/data/*.mmdb /tmp/geoip-data/`
3. Use this `named.conf` (full file):

   ```
   options {
       directory "/tmp/nstest";
       listen-on port 5353 proxy plain { 127.0.0.1; };
       listen-on-v6 { none; };
       match-mapped-addresses no;          /* the default; explicit for the test */
       geoip-directory "/tmp/geoip-data";
       recursion no;
       allow-query { !10.53.0.2; geoip country US; };
       allow-proxy { 127.0.0.1; };
   };
   zone "example" {
       type primary;
       file "example.db";                  /* any trivial primary zone */
   };
   ```

4. Start the server: `named -c named.conf`
5. Send three queries for `example/SOA` over TCP to 127.0.0.1:5353, each
   prefixed by a hand-built PROXY v2 header (test client `tools/pxtest.c`
   attached; it emits a spec-conformant v2 header followed by the query):
   - `pxtest 5353 v4` — PROXY v2 INET4, source `10.53.0.2`
   - `pxtest 5353 mapped` — PROXY v2 INET6, source `::ffff:10.53.0.2`
   - `pxtest 5353 none` — no PROXY header (control)
6. (Independent library-level confirmation) build the attached
   `tools/geoip-probe.c`
   (`gcc -o probe geoip-probe.c -lmaxminddb`) and run
   `./probe GeoIP2-Country.mmdb 10.53.0.2` against the fixture DB, then against
   any production GeoLite2-Country DB: plain IPv4, v4-mapped and v4-compatible
   lookups return the identical record and netmask.

## Current vs expected behavior

### Current (buggy) behavior

```
pxtest 5353 v4      (PROXY src 10.53.0.2)        -> rcode=REFUSED            (deny prefix fired - correct)
pxtest 5353 mapped  (PROXY src ::ffff:10.53.0.2) -> rcode=NOERROR, 1 answer  (*** the defect ***)
pxtest 5353 none    (no PROXY header)            -> connection dropped        (listener requires header - control)
```

The same physical client is refused as plain IPv4 but **allowed despite the
explicit `!10.53.0.2` exclusion** when its address arrives v4-mapped: the
radix deny honors `match_mapped=no`, while the GeoIP element matches anyway.
The ACL outcome for the same client is determined by the *encoding* of its
address, not by policy.

### Expected (correct) behavior

GeoIP elements should honor the configured `match-mapped-addresses` policy
exactly like prefix elements: with `no` (default), a v4-mapped address must
not match any IPv4-derived ACL content, including GeoIP lookups.

## Suggested fix

Minimal fix — in `dns_aclelement_match()` (`lib/dns/acl.c:384-388`):

```c
case dns_aclelementtype_geoip:
        if (env == NULL || env->geoip == NULL) {
                return false;
        }
        if (!env->match_mapped && reqaddr->family == AF_INET6 &&
            IN6_IS_ADDR_V4MAPPED(&reqaddr->type.in6))
        {
                return false;
        }
        return dns_geoip_match(reqaddr, env->geoip, &e->geoip_elem);
```

Optional defense in depth: normalize or reject v4-mapped addresses in
`isc__nm_valid_proxy_addresses()` (`lib/isc/netmgr/netmgr.c:2333`); pass the
converted `addr` (not `reqaddr`) to the element loop at `acl.c:176`. A
regression test mirroring `bin/tests/system/geoip2` with a v4-mapped client
and `match-mapped-addresses no` would lock the behavior in.

## Disclosure timeline

- **2026-09:** Discovered and verified against a live build and a production
  GeoLite2 database
- **2026-09:** Reported to ISC (confidential GitLab issue, `/label ~Bug ~Security`)
- **Public:** At ISC's discretion

---

**Discovered by:** Mohamed Amine MZOUGHI, KyubiSec
