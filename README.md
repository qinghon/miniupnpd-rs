
# miniupnpd rewrite from C code(3b3d2c05)

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


## config change 

some feature marco in config.h are merged/remove, the following is the list
if real need , tell me I can roll back

### merged

- `ENABLE_6FC_SERVICE` merge to `ipv6`
- `ENABLE_HTTP_DATE` merge to `strict`
- `DELAY_MSEARCH_RESPONSE` merge to `strict`
- `ADVERTISE_WANPPPCONN` merge to `strict`
- `RANDOMIZE_URLS` to `randomurl`

### removed
- `HAS_DUMMY_SERVICE`: only use `ENABLE_L3F_SERVICE`
- `SSDP_PACKET_MAX_LEN`: no limit for String impl
- `HAVE_IP_MREQN`: force enabled, base on rust cannot support [linux<3.2](https://doc.rust-lang.org/nightly/rustc/platform-support.html) 
- `ENABLE_NATPMP`: force enabled, nat-pmp/pcp is a really simple and suit protocol for the nat firewall , won't close it unless there is enough reason
- `USE_DAEMON`: use dynamic flag
- `ENABLE_LEASEFILE`: force enabled
- `ENABLE_L3F_SERVICE`: force enabled
- `USE_TIME_AS_BOOTID`: force enabled


### Not yet supported

- [ ] `ENABLE_GETIFSTATS_CACHING`
- [ ] `GETIFSTATS_CACHING_DURATION`
- [ ] `LEASEFILE_USE_REMAINING_TIME`
- [x] `CHECK_PORTINUSE`
- [ ] `V6SOCKETS_ARE_V6ONLY`
- [x] `ENABLE_HTTPS`
- [ ] `ENABLE_NFQUEUE`: when if real user need
- [x] `USE_SYSTEMD`
- [ ] `PF_SET_DST_ADDR`
- [ ] `MULTIPLE_EXTERNAL_IP`: need full refactor
- [x] `ENABLE_REGEX`
- [ ] `USE_IFNAME_IN_RULES`