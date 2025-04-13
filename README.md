
# miniupnpd rewrite from C code(f39e4997591a98e7ee6711eabc8b50feeef1bd67)

> [!WARNING] WIP Waring
> 
> This project has not yet completed a security review. Please do not deploy it in a production environment or on an open network lightly.

## why ?
Mainly based on interest

Other reasons:
- As part of the network infrastructure, miniupnpd has fewer vulnerability reports thanks to active maintenance, but the code is more confusing. 
- As a low-level language, C language will gradually have fewer maintainers, and switching to rust may inject new impetus into the community.

Of course , replace to rust will be take some defect:
- binary size
> rust complier difficult to reduce binary size in large projects
- platform support
> Due to language requirements, it is difficult to support some special platforms

# roadmap

## Step1: basic function port to rust
- [x] basic demo 
- [x] iptable backend
- [x] nftables backend
- [ ] function review
- [ ] security review
- [ ] evaluate binary size
- [ ] pf/ipfw
- [ ] ...

## Step2: simplify code

Use Rust's expressiveness to simplify code


## build

Currently, this project is compiled with the nightly toolchain because it needs to 
use build-std and some other unstable features to reduce the binary size.

### glibc
```shell

RUSTFLAGS="-Zlocation-detail=none -Zfmt-debug=none " cargo +nightly build -Z build-std=std,panic_abort -Z build-std-features="optimize_for_size" -Z build-std-features=panic_immediate_abort --features pcp_peer,strict -Z unstable-options  --release

```

### musl (alpine)
```shell
apk add libuuid libcap-ng-dev util-linux-dev
# depends by bindgen  
apk add clang-dev musl-dev llvm-dev 
# iptables
apk add iptables-dev 

# nftables
apk add libmnl-dev libnftnl-dev 

rustup component add rust-src

RUSTFLAGS="-Zlocation-detail=none -Zfmt-debug=none -C target-feature=-crt-static " cargo +nightly build -Z build-std=std,panic_abort -Z build-std-features="optimize_for_size" -Z build-std-features=panic_immediate_abort --features pcp_peer,strict -Z unstable-options  --release
```

## note

Currently, the project uses a significant amount of unsafe code to access cABI and reduce binary size. Due to the nature of the project, it is difficult to completely eliminate unsafe usage; 

however, we will gradually reduce its impact and conduct rigorous testing.
