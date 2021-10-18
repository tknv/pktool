# pktool 

## Developing

### Linux 

Just install Rust. No objection.

### Windows 

#### Setup 

- install c++ build tool: Ref: <https://stackoverflow.com/questions/55603111/unable-to-compile-rust-hello-world-on-windows-linker-link-exe-not-found>
- install Packet.lib to build tool libs: Ref: <https://crates.io/crates/pnet>
  - Check Windows section.
    - MSVC toolchain is installed with c++ build tool.
    - install *pcap
    - Place Packet.lib to `C:\Users\foo\.rustup\toolchains\stable-x86_64-pc-windows-msvc\lib\rustlib\x86_64-pc-windows-msvc\lib` : Ref: <https://github.com/libpnet/libpnet/issues/332#issuecomment-558512107>

If facing below error while building this source.

```bash
...Caused by:
failed to fetch https://github.com/rust-lang/crates.io-index

Caused by:
failed to authenticate when downloading repository
attempted ssh-agent authentication, but none of the usernames git succeeded

Caused by:
error authenticating: no auth sock variable; class=Ssh (23)
...
```

Add this to git config would fix it. Ref: <https://github.com/rust-lang/cargo/issues/8172#issuecomment-659066173>

```bash
[url "git@github.com:"]
        insteadOf = https://github.com/

[url "https://github.com/rust-lang/crates.io-index"]
        insteadOf = https://github.com/rust-lang/crates.io-index
```
