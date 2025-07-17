# eBPF TCP-Fingerprint Collector (JA4T)

This project is not yet in a stable state!

Test it: [fingerprint.oxl.app](https://fingerprint.oxl.app)

----

## Intro

About JA4:

* [JA4T TCP Fingerprinting](https://medium.com/foxio/ja4t-tcp-fingerprinting-12fb7ce9cb5a)
* [JA4+ Suite](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/README.md)
* [FoxIO Repository](https://github.com/FoxIO-LLC/ja4)
* [Cloudflare Blog](https://blog.cloudflare.com/ja4-signals)
* [FoxIO Blog](https://blog.foxio.io/ja4%2B-network-fingerprinting)
* [FoxIO JA4 Database](https://ja4db.com/)
* [JA4 HAProxy Lua Plugin](https://github.com/O-X-L/haproxy-ja4)
* [JA4H HAProxy Lua Plugin](https://github.com/O-X-L/haproxy-ja4h)

Browser Fingerprinting:
* [Browser Fingerprinting](https://github.com/O-X-L/browser-fingerprint)

----

## License

This script is licensed under the GPLv3-license and thus is free to use. If you modify it for your needs - you'll have to open-source the fork.

But the JA4T algorithm has some usage-limitations - see: [FoxIO-LLC/ja4](https://github.com/FoxIO-LLC/ja4?tab=readme-ov-file#licensing) & [JA4+ FoxIO License](https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE)

----

## Development

See eBPF documentation:
* [eBPF Docs](https://docs.ebpf.io/)
* [Learning eBPF](https://cilium.isovalent.com/hubfs/Learning-eBPF%20-%20Full%20book.pdf)
* [Cilium Docs](https://docs.cilium.io/en/latest/reference-guides/bpf/)

You will need:
* Docker to build the eBPF binary from C (*or install the build-dependencies as seen in the dockerfile locally..*)
* [Go in the required version](https://go.dev/doc/install) (*see go.mod*)
* Knowledge about how eBPF works
