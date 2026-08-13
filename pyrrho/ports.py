"""Port classification.

Whether opening a port to the internet is a critical finding or an expected one
depends entirely on what listens there. 443 open to the world is a web server.
5432 open to the world is a database on the internet. Encoding that difference
is what stops the tool from being either noisy or useless.
"""

from __future__ import annotations

from typing import Any

# Ports whose exposure to the internet is a design decision, not an incident.
PUBLIC_BY_DESIGN: dict[int, str] = {
    80: "HTTP",
    443: "HTTPS",
}

# Services that should never be reachable from the public internet. Exposure
# here is treated as critical regardless of what else the rule says.
ADMIN_AND_DATA: dict[int, str] = {
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    111: "rpcbind",
    135: "MSRPC",
    137: "NetBIOS",
    139: "NetBIOS/SMB",
    161: "SNMP",
    389: "LDAP",
    445: "SMB",
    512: "rexec",
    513: "rlogin",
    514: "rsh/syslog",
    636: "LDAPS",
    873: "rsync",
    1433: "MSSQL",
    1521: "Oracle DB",
    2049: "NFS",
    2375: "Docker API (plaintext)",
    2376: "Docker API (TLS)",
    2379: "etcd client",
    2380: "etcd peer",
    3000: "Grafana / dev server",
    3306: "MySQL",
    3389: "RDP",
    4505: "Salt master publish",
    4506: "Salt master return",
    5432: "PostgreSQL",
    5439: "Redshift",
    5601: "Kibana",
    5672: "AMQP",
    5900: "VNC",
    5984: "CouchDB",
    6379: "Redis",
    6443: "Kubernetes API",
    7000: "Cassandra internode",
    7001: "Cassandra SSL internode",
    8020: "HDFS NameNode",
    8086: "InfluxDB",
    8500: "Consul HTTP",
    8600: "Consul DNS",
    9042: "Cassandra CQL",
    9092: "Kafka",
    9200: "Elasticsearch HTTP",
    9300: "Elasticsearch transport",
    10250: "kubelet",
    11211: "memcached",
    15672: "RabbitMQ management",
    26257: "CockroachDB",
    27017: "MongoDB",
    27018: "MongoDB shard",
    50070: "HDFS NameNode UI",
}

# The whole port space, as Terraform expresses it in different providers.
ALL_PORTS = (0, 65535)

# AWS accepts either the IANA protocol number or its name, and Terraform passes
# through whichever the author wrote. `protocol = "6"` and `protocol = "tcp"` are
# the same rule; a checker that compares the string sees two different ones.
PROTOCOL_NUMBERS: dict[str, str] = {
    "1": "icmp",
    "6": "tcp",
    "17": "udp",
    "41": "ipv6",
    "47": "gre",
    "50": "esp",
    "51": "ah",
    "58": "icmpv6",
    "132": "sctp",
}

ANY_PROTOCOL = {"-1", "all"}


def canonical_protocol(protocol: Any) -> str:
    """One spelling per protocol, so rules can be compared and paired."""
    text = str(protocol or "").strip().lower()
    if text in ANY_PROTOCOL:
        return "-1"
    return PROTOCOL_NUMBERS.get(text, text)


def is_all_ports(from_port: int | None, to_port: int | None, protocol: str) -> bool:
    """True when the rule covers every port of every protocol.

    AWS expresses "all traffic" as protocol ``-1`` with the ports unset, and
    also accepts an explicit 0-65535 TCP range, which is the same thing for TCP.
    """
    if canonical_protocol(protocol) == "-1":
        return True
    if from_port is None or to_port is None:
        return False
    return from_port <= ALL_PORTS[0] and to_port >= ALL_PORTS[1]


def covered(from_port: int | None, to_port: int | None) -> range | None:
    """The inclusive port range as a Python range, or None when unbounded."""
    if from_port is None or to_port is None:
        return None
    lo, hi = sorted((int(from_port), int(to_port)))
    return range(lo, hi + 1)


def sensitive_in_range(from_port: int | None, to_port: int | None, protocol: str) -> dict[int, str]:
    """Every admin/data service the rule exposes, keyed by port.

    A range like 1024-65535 is not "one port"; it swallows Redis, Elasticsearch,
    MongoDB and the kubelet in a single line that reads as innocuous in a diff.
    """
    if is_all_ports(from_port, to_port, protocol):
        return dict(ADMIN_AND_DATA)
    span = covered(from_port, to_port)
    if span is None:
        return {}
    return {port: name for port, name in ADMIN_AND_DATA.items() if port in span}


def describe(from_port: int | None, to_port: int | None, protocol: str) -> str:
    """Human label for the port range, used in messages and evidence."""
    proto = canonical_protocol(protocol)
    if is_all_ports(from_port, to_port, protocol):
        return "all ports, all protocols" if proto == "-1" else f"all {proto} ports"
    if from_port is None or to_port is None:
        return f"{proto} (unspecified ports)"
    if from_port == to_port:
        label = ADMIN_AND_DATA.get(int(from_port)) or PUBLIC_BY_DESIGN.get(int(from_port))
        suffix = f" [{label}]" if label else ""
        return f"{proto}/{from_port}{suffix}"
    return f"{proto}/{from_port}-{to_port}"
