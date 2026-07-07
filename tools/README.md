# Caliptra DPE Certificate Visualizer (`caliptra-dpe-tools`)

`caliptra-dpe-tools` is a 100% client-side WebAssembly (WASM) browser application for parsing, inspecting, and visualizing DICE and DPE (Data Protection Engine) X.509 certificates and Certificate Signing Requests (CSRs).

---

## Features

- **X.509 Certificate & CSR Parsing**: Decodes standard X.509 V3 certificates and PKCS#10 Certificate Signing Requests (CSRs).
- **DICE MultiTcbInfo / TcbInfo OID Extraction**: Parses `2.23.133.5.4.5` (`tcg-dice-MultiTcbInfo`) and `2.23.133.5.4.1` (`tcg-dice-TcbInfo`) ASN.1 structures into TCB context nodes.
- **TCB Context Graphing**: Constructs a directed acyclic graph (DAG) representing the DPE TCB context derivation chain.
- **DPE Profile Inference**: Inspects public key types (ECC P-256, P-384, ML-DSA), signature algorithms, and FWID OIDs (SHA-256 vs. SHA-384) to automatically infer the active DPE profile (e.g. `P256-SHA256`, `P384-SHA384`, `MLDSA-87`).

---

## WASM Visualizer Usage

The WASM visualizer runs entirely in the browser with **zero backend server latency** or remote API dependencies.

### Quick Start with `xtask`

Build the WASM module, generate JS bindings, and start a local HTTP server in one command:

```bash
nix develop
cargo xtask cert-graph --serve
```

Then open **[http://localhost:8080](http://localhost:8080)** in your browser.

### WASM Command Options

| Command / Flag | Description |
| :--- | :--- |
| `cargo xtask cert-graph` | Builds the WASM library (`tools/pkg/`) without launching the web server. |
| `cargo xtask cert-graph --serve` | Builds WASM and starts local HTTP server at `http://localhost:8080`. |
| `cargo xtask cert-graph --serve --port 9090` | Hosts the visualizer on a custom HTTP port. |

### Web Application Capabilities

- **Drag & Drop**: Drag `.der`, `.pem`, or DPE binary packets directly into the browser window.
- **Sample Loader**: Load a multi-branching DPE certificate generated at build-time with one click.
- **Interactive Graphs**: Live rendering of Mermaid.js flowcharts and GitHub-flavored Markdown tables.

---

## Architecture & Code Structure

```
tools/
├── Cargo.toml            # Configures cdylib for wasm32 and host support tools
├── build.rs              # Generates sample branching DPE cert at build time
├── index.html            # Single-page web visualizer (drag-and-drop, Mermaid.js, marked.js)
├── pkg/                  # Generated wasm-bindgen JS and .wasm artifacts
└── src/
    ├── lib.rs            # Shared core: ASN.1 decoders, graph builder, Markdown renderer, WASM exports
    ├── sample_dpe_cert.rs # Support tool: Generates sample DPE certificate
    └── cert_size/        # Support tool: Measures certificate size benchmarks
```

- **`tools/src/lib.rs`**: Contains all ASN.1 decoding (`asn1`), Mermaid graph generation, and markdown generation logic. When compiled for `wasm32-unknown-unknown` target, it exposes `render_dpe_cert_markdown()` and `get_default_sample_pem()`.
- **Target Isolation**: Host-only DPE instance dependencies (`caliptra-dpe`, etc.) are restricted under `target.'cfg(not(target_arch = "wasm32"))'.dependencies`, ensuring the WASM library remains lightweight.
