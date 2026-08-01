# ndn-ndnlp

[![docs.rs](https://img.shields.io/docsrs/ndn-ndnlp)](https://docs.rs/ndn-ndnlp)
[![crates.io](https://img.shields.io/crates/v/ndn-ndnlp)](https://crates.io/crates/ndn-ndnlp)
[![license](https://img.shields.io/crates/l/ndn-ndnlp)](https://github.com/ndn-cluster-rs/ndn-ndnlp/blob/master/LICENSE)

A partial implementation of NDNLPv2, the link-layer protocol NDN packets are framed in before being sent over a transport.

This crate only implements the parts of NDNLPv2 that [`ndn-app`](https://crates.io/crates/ndn-app) needs -- it is not a complete implementation of the protocol.

## Installation

```
cargo add ndn-ndnlp
```

## How it works

- `Packet` is the union of everything that can appear directly on the wire: a bare Interest, a bare Data packet, or an NDNLPv2 `LpPacket`.
- `LpPacket` wraps a fragment of an Interest or Data with link-layer metadata -- a sequence number and fragment index/count for reassembly, or a link-layer Nack instead of a fragment.
- Headers this crate doesn't have a dedicated type for are preserved as `UnknownHeader` rather than dropped.

## Related crates

- [`ndn-app`](https://crates.io/crates/ndn-app) is an application framework that uses this crate for its link-layer framing.
- [`ndn-tlv`](https://crates.io/crates/ndn-tlv) provides the TLV encoding/decoding traits this crate's packet types are built on.
- [`ndn-protocol`](https://crates.io/crates/ndn-protocol) implements the Interest and Data packet types this crate frames.

## License

MIT

---

Produced as part of a Master's thesis in Computer Science.
