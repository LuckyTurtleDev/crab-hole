# 🦀 crab-hole
![License: AGPL-3.0-or-later](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue)
[![crab-hole on crates.io](https://img.shields.io/crates/v/crab-hole)](https://crates.io/crates/crab-hole)
[![Source Code Repository](https://img.shields.io/badge/Code-On%20GitHub-blue?logo=GitHub)](https://github.com/LuckyTurtleDev/crab-hole)
[![Packaging status](https://repology.org/badge/tiny-repos/crab-hole.svg)](https://repology.org/project/crab-hole/versions) 
[![AUR package](https://repology.org/badge/version-for-repo/aur/crab-hole.svg)](https://aur.archlinux.org/packages/crab-hole)

Crab-hole is a cross platform Pi-hole clone written in Rust using [hickory-dns/trust-dns](https://github.com/hickory-dns/hickory-dns).
It can be used as a network wide Ad and spy blocker or run on your local pc.

For a secure and private communication, crab-hole has builtin support for doh(https), doq(quic) and dot(tls) for down- and upstreams and dnssec for upstreams.
It also comes with privacy friendly default logging settings.

# Installation: 
Crab-hole is available in the following repositories:

[![Packaging status](https://repology.org/badge/vertical-allrepos/crab-hole.svg)](https://repology.org/project/crab-hole/versions)

Prebuilt binaries can also been downloaded from the [Github release](https://github.com/LuckyTurtleDev/crab-hole/releases/latest).


### Building from source: 
Alternatively you can easily build crab-hole yourself.
* [Install Rust](https://www.rust-lang.org/tools/install)
* Run `cargo install crab-hole --locked`
See the [Rust book](https://doc.rust-lang.org/cargo/commands/cargo-install.html) for more information about cargo install.
* Make sure that `~/.cargo/bin` is listed in the `PATH` environment variable

### Docker
A docker image is available at the Github Container Registry.
Example `docker-compose.yml`:
```yml
version: '3.3'
services:
    crab-hole:
        image: 'ghcr.io/luckyturtledev/crab-hole:latest' #semver tags are available
        ports: #required ports depend on downstream configuration
            - "53:53/tcp"
            - "53:53/udp"
        volumes:
            - './data:/data'
            - './config.toml:/data/config.toml:ro'
```
[Semver](https://semver.org/) tags like `v0`, `v0.1` and `v0.1.3` are available to safely allow automatic updates.

# Configuration:
Example config file using cloudflare as dot (dns-over-tls) upstream.
<!-- test_config -->
```toml
[blocklist]
include_subdomains = true
lists = [
	"https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn/hosts",
	"https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
	"file:///blocked.txt"
]
# allow domains blocked by the blocklist again
allow_list = ["file:///allowed.txt"]

# optional
[api]
port = 8080
listen = "127.0.0.1"
# optional (default = false)
show_doc = true # OpenAPI doc loads content from third party websites
# optional
admin_key = "1234"

[[downstream]]
protocol = "udp"
listen = "localhost"
port = 8080

[[downstream]]
protocol = "udp"
listen = "[::]" #all ipv6 and ipv4 adress
port = 8053

[[downstream]]
protocol = "tls"
listen = "[::]"
port = 8054
certificate = "dns.example.com.crt"
key = "dns.example.com.key"
# optional (default = 3000)
timeout_ms = 3000

[[downstream]]
protocol = "https"
listen = "[::]"
port = 8055
certificate = "dns.example.com.crt"
key = "dns.example.com.key"
dns_hostname = "dns.example.com"
# optional (default = 3000)
timeout_ms = 3000

[[downstream]]
protocol = "quic"
listen = "127.0.0.1"
port = 8055
certificate = "dns.example.com.crt"
key = "dns.example.com.key"
dns_hostname = "dns.example.com"
# optional (default = 3000)
timeout_ms = 3000

[[downstream]]
protocol = "h3"
listen = "127.0.0.1"
port = 8443
certificate = "dns.example.com.crt"
key = "dns.example.com.key"
dns_hostname = "dns.example.com"
# optional (default = 3000)
timeout_ms = 3000

# optional
[upstream.options]
# optional (default = false)
# Keep DNSSEC disabled due to Hickory DNS issue, see https://github.com/hickory-dns/hickory-dns/issues/2429
# validate = true # use DNSSEC
# see https://docs.rs/hickory-resolver/0.24/hickory_resolver/config/struct.ResolverOpts.html for all options

[[upstream.name_servers]]
socket_addr = "[2606:4700:4700::1111]:853"
protocol = "tls"
tls_dns_name = "1dot1dot1dot1.cloudflare-dns.com"
trust_negative_responses = false

[[upstream.name_servers]]
socket_addr = "[2606:4700:4700::1001]:853"
protocol = "tls"
tls_dns_name = "1dot1dot1dot1.cloudflare-dns.com"
trust_negative_responses = false

[[upstream.name_servers]]
socket_addr = "1.1.1.1:853"
protocol = "tls"
tls_dns_name = "1dot1dot1dot1.cloudflare-dns.com"
trust_negative_responses = false

[[upstream.name_servers]]
socket_addr = "1.0.0.1:853"
protocol = "tls"
tls_dns_name = "1dot1dot1dot1.cloudflare-dns.com"
trust_negative_responses = false
```

## Starting the Server
To start the server just execute the binary without any subcommands.

`crab-hole`

## Syntax check
To check if the config has a valid syntax, the following command can be used.

`crab-hole validate-config`

This loads the config to check for syntax issues, but does not start the DNS server.

## Validation
The config and blocklists can be validated by running the following command.

`crab-hole validate-lists`

This only validates the config, block- and allowlists, and does not start the DNS server. If the validation fails, the program exits with the error code `1`.

## DNSSEC Issues
Due to an upstream issue of [hickory-dns](https://github.com/hickory-dns/hickory-dns/issues/2429), non DNSSEC sites will not be resolved if `validate = true`.
Only DNSSEC capable sites will be resolved with this setting.
To prevent this, set `validate = false` or omit the `[upstream.options]`.
