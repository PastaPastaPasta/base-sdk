[![GitHub License](https://img.shields.io/github/license/dashpay/base-sdk?style=flat&logo=readme&logoColor=white)](./LICENSE)
![Minimum Supported Rust Version](https://img.shields.io/badge/v1.89.0-msrv?style=flat&logo=rust&label=MSRV&color=orange)

> [!WARNING]
>
> This SDK is in early stages of development and different crates may have different levels of conformance and
> testing rigour. The completeness of one crate does not imply the completeness of others.
>
> As with any alternate implementation, unintended deviations from the reference implementation (i.e.
> [Dash Core](https://github.com/dashpay/dash)) are possible and must be accounted for as a risk when building on
> this SDK. If requirements demand strict conformance guarantees, it is recommended to interface with Dash Core
> through [RPC](https://docs.dash.org/en/stable/docs/core/api/remote-procedure-calls.html),
> [REST](https://docs.dash.org/en/stable/docs/core/api/http-rest.html) or
> [ZMQ](https://docs.dash.org/en/stable/docs/core/api/zmq.html) instead.

`base-sdk` is a parsing and stateless verification SDK for Dash's layer 1 blockchain.

<!-- [start:crate-info] -->

| Crate | Description | CI | Coverage | Version |
| --- | --- | --- | --- | --- |
| [dash-num](./pkgs/num) | Hash blobs, 256-bit arithmetic, compact target encoding | [![dash-num](https://img.shields.io/github/actions/workflow/status/dashpay/base-sdk/pkg_num.yml?style=flat&logo=github&logoColor=white&label=num)](https://github.com/dashpay/base-sdk/actions/workflows/pkg_num.yml) | [![dash-num](https://img.shields.io/codecov/c/github/dashpay/base-sdk/develop?flag=dash-num&style=flat&logo=codecov&logoColor=white&label=num)](https://app.codecov.io/github/dashpay/base-sdk/tree/develop/pkgs%2Fnum) | [![dash-num](https://img.shields.io/crates/v/dash-num?style=flat&logo=hackthebox&logoColor=white&label=num&color=teal)](https://crates.io/crates/dash-num) |
| [dash-p2p-core](./pkgs/p2p_core) | P2P message types and wire format | [![dash-p2p-core](https://img.shields.io/github/actions/workflow/status/dashpay/base-sdk/pkg_p2p_core.yml?style=flat&logo=github&logoColor=white&label=p2p-core)](https://github.com/dashpay/base-sdk/actions/workflows/pkg_p2p_core.yml) | [![dash-p2p-core](https://img.shields.io/codecov/c/github/dashpay/base-sdk/develop?flag=dash-p2p-core&style=flat&logo=codecov&logoColor=white&label=p2p-core)](https://app.codecov.io/github/dashpay/base-sdk/tree/develop/pkgs%2Fp2p_core) | _Unreleased._ |
| [dash-params](./pkgs/params) | Chain parameters for `mainnet`, `testnet3`, devnets and `regtest`, by release | [![dash-params](https://img.shields.io/github/actions/workflow/status/dashpay/base-sdk/pkg_params.yml?style=flat&logo=github&logoColor=white&label=params)](https://github.com/dashpay/base-sdk/actions/workflows/pkg_params.yml) | [![dash-params](https://img.shields.io/codecov/c/github/dashpay/base-sdk/develop?flag=dash-params&style=flat&logo=codecov&logoColor=white&label=params)](https://app.codecov.io/github/dashpay/base-sdk/tree/develop/pkgs%2Fparams) | _Unreleased._ |
| [dash-pkc](./pkgs/pkc) | BLS (legacy + IETF) and secp256k1 operations | [![dash-pkc](https://img.shields.io/github/actions/workflow/status/dashpay/base-sdk/pkg_pkc.yml?style=flat&logo=github&logoColor=white&label=pkc)](https://github.com/dashpay/base-sdk/actions/workflows/pkg_pkc.yml) | [![dash-pkc](https://img.shields.io/codecov/c/github/dashpay/base-sdk/develop?flag=dash-pkc&style=flat&logo=codecov&logoColor=white&label=pkc)](https://app.codecov.io/github/dashpay/base-sdk/tree/develop/pkgs%2Fpkc) | [![dash-pkc](https://img.shields.io/crates/v/dash-pkc?style=flat&logo=hackthebox&logoColor=white&label=pkc&color=teal)](https://crates.io/crates/dash-pkc) |
| [dash-pow](./pkgs/pow) | Proof of work scheme | [![dash-pow](https://img.shields.io/github/actions/workflow/status/dashpay/base-sdk/pkg_pow.yml?style=flat&logo=github&logoColor=white&label=pow)](https://github.com/dashpay/base-sdk/actions/workflows/pkg_pow.yml) | [![dash-pow](https://img.shields.io/codecov/c/github/dashpay/base-sdk/develop?flag=dash-pow&style=flat&logo=codecov&logoColor=white&label=pow)](https://app.codecov.io/github/dashpay/base-sdk/tree/develop/pkgs%2Fpow) | [![dash-pow](https://img.shields.io/crates/v/dash-pow?style=flat&logo=hackthebox&logoColor=white&label=pow&color=teal)](https://crates.io/crates/dash-pow) |
| [dash-primitives](./pkgs/primitives) | Blocks, transactions, payloads, governance objects | [![dash-primitives](https://img.shields.io/github/actions/workflow/status/dashpay/base-sdk/pkg_primitives.yml?style=flat&logo=github&logoColor=white&label=primitives)](https://github.com/dashpay/base-sdk/actions/workflows/pkg_primitives.yml) | [![dash-primitives](https://img.shields.io/codecov/c/github/dashpay/base-sdk/develop?flag=dash-primitives&style=flat&logo=codecov&logoColor=white&label=primitives)](https://app.codecov.io/github/dashpay/base-sdk/tree/develop/pkgs%2Fprimitives) | _Unreleased._ |
| [dash-script](./pkgs/script) | Script opcodes, classification, and address derivation | [![dash-script](https://img.shields.io/github/actions/workflow/status/dashpay/base-sdk/pkg_script.yml?style=flat&logo=github&logoColor=white&label=script)](https://github.com/dashpay/base-sdk/actions/workflows/pkg_script.yml) | [![dash-script](https://img.shields.io/codecov/c/github/dashpay/base-sdk/develop?flag=dash-script&style=flat&logo=codecov&logoColor=white&label=script)](https://app.codecov.io/github/dashpay/base-sdk/tree/develop/pkgs%2Fscript) | _Unreleased._ |
| [dash-types](./pkgs/types) | Shared byte and integer newtypes, serde helpers | [![dash-types](https://img.shields.io/github/actions/workflow/status/dashpay/base-sdk/pkg_types.yml?style=flat&logo=github&logoColor=white&label=types)](https://github.com/dashpay/base-sdk/actions/workflows/pkg_types.yml) | [![dash-types](https://img.shields.io/codecov/c/github/dashpay/base-sdk/develop?flag=dash-types&style=flat&logo=codecov&logoColor=white&label=types)](https://app.codecov.io/github/dashpay/base-sdk/tree/develop/pkgs%2Ftypes) | [![dash-types](https://img.shields.io/crates/v/dash-types?style=flat&logo=hackthebox&logoColor=white&label=types&color=teal)](https://crates.io/crates/dash-types) |

<!-- [end:crate-info] -->

## System Requirements

See [`dash-pow`](./pkgs/pow/README.md) for more information.

## Documentation

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/dashpay/base-sdk)

Documentation is hosted at <https://dashpay.github.io/base-sdk>. To render it locally or learn its syntax, visit the
[getting started](https://dashpay.github.io/base-sdk/dev/about_docs) guide. Release notes for published crates are
listed below.

* [`dash-num`](./pkgs/num/CHANGELOG.md)
* [`dash-pkc`](./pkgs/pkc/CHANGELOG.md)
* [`dash-pow`](./pkgs/pow/CHANGELOG.md)
* [`dash-types`](./pkgs/types/CHANGELOG.md)

## Licensing

Copyright &copy; 2026-present, The Dash Core developers. See the accompanying file [LICENSE](./LICENSE) or
<https://opensource.org/license/MIT>
