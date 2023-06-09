# 🦀 crab-hole
![License: AGPL-3.0-or-later](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue)
[![crab-hole on crates.io](https://img.shields.io/crates/v/crab-hole)](https://crates.io/crates/crab-hole)
[![Source Code Repository](https://img.shields.io/badge/Code-On%20GitHub-blue?logo=GitHub)](https://github.com/LuckyTurtleDev/crab-hole)
[![Packaging status](https://repology.org/badge/tiny-repos/crab-hole.svg)](https://repology.org/project/crab-hole/versions) 
[![AUR package](https://repology.org/badge/version-for-repo/aur/crab-hole.svg)](https://aur.archlinux.org/packages/crab-hole)

Crab-hole is a cross platform Pi-hole clone written in rust using [trust-dns](https://github.com/bluejekyll/trust-dns).
It can be use as network wide Ad and spy blocker or just run it on your local pc.

For a secure and private communication carb-hole has buildin support for doh(https), doq(quic), dot(tls) and dnssec for upstreams.
And does also come with private friendly default logging settings.

# Installation: 
Crab-hole is avaibale at the following repositories:

[![Packaging status](https://repology.org/badge/vertical-allrepos/crab-hole.svg)](https://repology.org/project/crab-hole/versions)

Prebuild binarys can also been downloaded from the [Github release](https://github.com/LuckyTurtleDev/crab-hole/releases/latest).


### Building from source: 
Alternative you can easily build crab-hole by yourself.
* [install rust](https://www.rust-lang.org/tools/install)
* run `cargo install crab-hole --locked`.
See the [rust book](https://doc.rust-lang.org/cargo/commands/cargo-install.html) for more information about cargo install.
* make sure that `~/.cargo/bin` is listed at the `PATH` enviroment variable

# Configuration:
Example config file using cloudflare as dot (dns-over-tls) upstream.
```toml
[blocklist]
include_subdomains = true
lists = [
	"https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn/hosts"
]

[[downstream]]
protocol = "udp"
listen = "localhost"
port = 8080

[[downstream]]
protocol = "udp"
listen = "[::]" #all ipv6 and ipv4 adress
port = 8053

[[upstream.name_servers]]
socket_addr = "[2606:4700:4700::1111]:853"
protocol = "tls"
tls_dns_name = "1dot1dot1dot1.cloudflare-dns.com"
trust_nx_responses = false

[[upstream.name_servers]]
socket_addr = "[2606:4700:4700::1001]:853"
protocol = "tls"
tls_dns_name = "1dot1dot1dot1.cloudflare-dns.com"
trust_nx_responses = false

[[upstream.name_servers]]
socket_addr = "1.1.1.1:853"
protocol = "tls"
tls_dns_name = "1dot1dot1dot1.cloudflare-dns.com"
trust_nx_responses = false

[[upstream.name_servers]]
socket_addr = "1.0.0.1:853"
protocol = "tls"
tls_dns_name = "1dot1dot1dot1.cloudflare-dns.com"
trust_nx_responses = false
```
