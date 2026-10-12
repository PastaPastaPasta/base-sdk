# Introduction

The Base SDK for Dash is a collection of packages that enable applications to parse, construct and interact with the
Dash blockchain. This is achieved by leveraging the [`rust-bitcoin`](https://github.com/rust-bitcoin/rust-bitcoin)
ecosystem to provide a framework that builds upon existing, familiar APIs and contract expectations.

To achieve this, state-independent portions of the consensus engine have been split into composable packages that can be
imported as needed.

<!-- [include:README.md:crate-info] -->

## Is the SDK a full node?

The Base SDK is not a full node implementation nor does it intend to be. `no_std` + `alloc` restricts I/O and networking
making it better suited for resource-constrained, sandboxed or otherwise limited environments. The public contract
reflects this, restricted to only stateless or relatively context-independent portions of the overall consensus engine.

For a more batteries-included solution, consider [`rust-dashcore`](https://github.com/dashpay/rust-dashcore) or the C++
reference implementation, [Dash Core](https://github.com/dashpay/dash) over
[RPC](https://docs.dash.org/en/stable/docs/core/api/remote-procedure-calls.html),
[REST](https://docs.dash.org/en/stable/docs/core/api/http-rest.html) or
[ZMQ](https://docs.dash.org/en/stable/docs/core/api/zmq.html).
