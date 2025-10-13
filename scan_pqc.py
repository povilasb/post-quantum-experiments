import subprocess
import typing as t

from scapy.layers.tls.all import TLS
from scapy.layers.inet import IP
from scapy.layers.tls.all import TLSClientHello, TLSServerHello
from scapy.sessions import TCPSession
from scapy.layers.tls.extensions import TLS_Ext_SupportedGroups
from scapy.layers.tls.keyexchange_tls13 import TLS_Ext_KeyShare_SH
from scapy.all import sniff, load_layer
from scapy.packet import Packet
import rich


TLS_VERSION = {
    0x0002: "SSLv2",
    0x0200: "SSLv2",
    0x0300: "SSLv3",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x7F12: "TLS 1.3-d18",
    0x7F13: "TLS 1.3-d19",
    0x0304: "TLS 1.3",
}

TLS_KEY_EXCHANGE_CIPHER_GROUPS = {
    # https://www.ietf.org/archive/id/draft-kwiatkowski-tls-ecdhe-mlkem-02.html#name-secp256r1mlkem768
    4587: "SecP256r1MLKEM768",
    # https://www.ietf.org/archive/id/draft-kwiatkowski-tls-ecdhe-mlkem-02.html#name-x25519mlkem768
    4588: "X25519MLKEM768",
    # https://www.ietf.org/archive/id/draft-tls-westerbaan-xyber768d00-03.html#name-iana-considerations
    0x6399: "X25519Kyber768Draft00",
    # Taken from scapy/layers/tls/crypto/groups.py
    256: "ffdhe2048",
    257: "ffdhe3072",
    258: "ffdhe4096",
    259: "ffdhe6144",
    260: "ffdhe8192",
    1: "sect163k1",
    2: "sect163r1",
    3: "sect163r2",
    4: "sect193r1",
    5: "sect193r2",
    6: "sect233k1",
    7: "sect233r1",
    8: "sect239k1",
    9: "sect283k1",
    10: "sect283r1",
    11: "sect409k1",
    12: "sect409r1",
    13: "sect571k1",
    14: "sect571r1",
    15: "secp160k1",
    16: "secp160r1",
    17: "secp160r2",
    18: "secp192k1",
    19: "secp192r1",
    20: "secp224k1",
    21: "secp224r1",
    22: "secp256k1",
    23: "secp256r1",
    24: "secp384r1",
    25: "secp521r1",
    26: "brainpoolP256r1",
    27: "brainpoolP384r1",
    28: "brainpoolP512r1",
    29: "x25519",
    30: "x448",
    0xFF01: "arbitrary_explicit_prime_curves",
    0xFF02: "arbitrary_explicit_char2_curves",
}

POST_QUANTUM_SAFE = {
    "X25519Kyber768Draft00",
    "X25519MLKEM768",
    "SecP256r1MLKEM768",
}


def main():
    load_layer("tls")
    sniff(prn=_handle_packet, session=TCPSession, store=False)


def _handle_packet(packet: Packet):
    ip_layer = packet.getlayer(IP)

    if tls_chlo := packet.getlayer(TLSClientHello):
        key_exchange_ciphers = []
        for extension in tls_chlo.ext:
            if isinstance(extension, TLS_Ext_SupportedGroups):
                key_exchange_ciphers.extend(
                    [
                        TLS_KEY_EXCHANGE_CIPHER_GROUPS.get(group, group)
                        for group in extension.groups
                    ]
                )

        if any(cipher in POST_QUANTUM_SAFE for cipher in key_exchange_ciphers):
            pq_safe_tag = "[green]PQ-SAFE[/green]"
        else:
            pq_safe_tag = "[red]PQ-UNSAFE[/red]"

        rich.print(
            f"-> CHLO[{pq_safe_tag}]: [{TLS_VERSION[tls_chlo.version]}] {ip_layer.src}:{ip_layer.sport} -> {ip_layer.dst}:{ip_layer.dport}: {key_exchange_ciphers} {_get_process_by_port(ip_layer.dport, 'tcp') or ''}"
        )

    elif tls_server_hello := packet.getlayer(TLSServerHello):
        selected_key_exchange_cipher = None
        for extension in tls_server_hello.ext:
            if isinstance(extension, TLS_Ext_KeyShare_SH):
                selected_key_exchange_cipher = TLS_KEY_EXCHANGE_CIPHER_GROUPS.get(
                    extension.server_share.group, extension.server_share.group
                )

        if selected_key_exchange_cipher in POST_QUANTUM_SAFE:
            pq_safe_tag = "[green]PQ-SAFE[/green]"
        else:
            pq_safe_tag = "[red]PQ-UNSAFE[/red]"
        rich.print(
            f"<- SHLO[{pq_safe_tag}]: [{TLS_VERSION[tls_server_hello.version]}] {ip_layer.src}:{ip_layer.sport} -> {ip_layer.dst}:{ip_layer.dport}: {selected_key_exchange_cipher}"
        )


def _get_process_by_port(
    port: int, transport_proto: t.Literal["tcp", "udp"]
) -> str | None:
    """Get process name and PID for a given port."""
    try:
        # Use lsof to find the process using this port
        # -n: no DNS resolution, -P: no port name resolution, -i: internet addresses
        result = subprocess.run(
            ["lsof", "-n", "-P", "-i", f"{transport_proto}:{port}"],
            capture_output=True,
            text=True,
            timeout=1,
        )

        if result.returncode == 0 and result.stdout:
            # Parse lsof output (skip header line)
            lines = result.stdout.strip().split("\n")
            if len(lines) > 1:
                # Parse the first data line
                parts = lines[1].split()
                process_name = parts[0]
                return f"{process_name}"
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, IndexError):
        pass

    return None


main()
