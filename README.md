# About

Post quantum crypto examples:

```sh
cargo run --bin server
cargo run --bin client # connects to localhost by default
cargo run --bin client -- 192.168.1.13:8443
```

## Network analysis

There's a little Python script that tries to guess if applications
are using post-quantom cryptogrpahy or not based on network traffic analysis.

Install [uv](https://docs.astral.sh/uv/).

```
uv sync
sudo uv run scan_pqc.py
```

## References

* https://pqc.lt
* https://pq.cloudflareresearch.com
