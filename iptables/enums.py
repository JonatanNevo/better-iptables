from enum import Enum


class ConnbytesDirection(str, Enum):
    ORIGINAL = "original"
    REPLY = "reply"
    BOTH = "both"


class ConnbytesMode(str, Enum):
    BYTES = "bytes"
    PACKETS = "packets"
    AVGERAGE = "avgpkt"


class ConntrackStates(str, Enum):
    INVALID = "INVALID"
    ESTABLISHED = "ESTABLISHED"
    RELATED = "RELATED"
    UNTRACKED = "UNTRACKED"
    SNAT = "SNAT"
    DNAT = "DNAT"
    NEW = "NEW"


class ConntrackStatus(str, Enum):
    NONE = "NONE"
    EXPECTED = "EXPECTED"
    SEEN_REPLY = "SEEN_REPLY"
    ASSURED = "ASSURED"
    CONFIRMED = "CONFIRMED"


class ConntrackDirection(str, Enum):
    ORIGINAL = "original"
    REPLY = "reply"


class LimitUnits(str, Enum):
    SECOND = "second"
    MINUTE = "minute"
    HOUR = "hour"
    DAY = "day"


class State(str, Enum):
    INVALID = "INVALID"
    ESTABLISHED = "ESTABLISHED"
    NEW = "NEW"
    RELATED = "RELATED"
    UNTRACKED = "UNTRACKED"


class TcpFlags(str, Enum):
    SYN = "SYN"
    ACK = "ACK"
    FIN = "FIN"
    RST = "RST"
    URG = "URG"
    PSH = "PSH"
    ALL = "ALL"
    NONE = "NONE"


class Targets(str, Enum):
    ACCEPT = "ACCEPT"
    DROP = "DROP"
    RETURN = "RETURN"
    AUDIT = "AUDIT"
    CHECKSUM = "CHECKSUM"
    CLASSIFY = "CLASSIFY"
    CLUSTERIP = "CLUSTERIP"
    CONNMARK = "CONNMARK"
    CONNSECMARK = "CONNSECMARK"
    CT = "CT"
    DNAT = "DNAT"
    DNPT = "DNPT"
    DSCP = "DSCP"
    ECN = "ECN"
    HL = "HL"
    HMARK = "HMARK"
    IDLETIMER = "IDLETIMER"
    LED = "LED"
    LOG = "LOG"
    MARK = "MARK"
    MASQUERADE = "MASQUERADE"
    NETMAP = "NETMAP"
    NFLOG = "NFLOG"
    NFQUEUE = "NFQUEUE"
    NOTRACK = "NOTRACK"
    RATEEST = "RATEEST"
    REDIRECT = "REDIRECT"
    REJECT = "REJECT"
    SECMARK = "SECMARK"
    SET = "SET"
    SNAT = "SNAT"
    SNPT = "SNPT"
    SYNPROXY = "SYNPROXY"
    TCPMSS = "TCPMSS"
    TCPOPTSTRIP = "TCPOPTSTRIP"
    TEE = "TEE"
    TOS = "TOS"
    TPROXY = "TPROXY"
    TRACE = "TRACE"
    TTL = "TTL"
    ULOG = "ULOG"


class Protocols(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ALL = "all"


class Tables(str, Enum):
    FILTER = "filter"
    NAT = "nat"
    MANGLE = "mangle"
    RAW = "raw"
    SECURITY = "security"


class Chains(str, Enum):
    INPUT = "INPUT"
    FORWARD = "FORWARD"
    OUTPUT = "OUTPUT"
    PREROUTING = "PREROUTING"
    POSTROUTING = "POSTROUTING"


class Actions(str, Enum):
    APPEND = "-A"
    DELETE = "-D"
    INSERT = "-I"
    REPLACE = "-R"
    CHECK = "-C"
    LIST = "-L"
    FLUSH = "-F"
    ZERO = "-Z"
    NEW_CHAIN = "-N"
    DELETE_CHAIN = "-X"
    RENAME_CHAIN = "-E"
    POLICY = "-P"
    LIST_RULES = "-S"


class RejectType(str, Enum):
    ICMP_NET_UNREACHABLE = "icmp-net-unreachable"
    ICMP_HOST_UNREACHABLE = "icmp-host-unreachable"
    ICMP_PORT_UNREACHABLE = "icmp-port-unreachable"
    ICMP_PROT_UNREACHABLE = "icmp-proto-unreachable"
    ICMP_NET_PROHIBITED = "icmp-net-prohibited"
    ICMP_HOST_PROHIBITED = "icmp-host-prohibited"
    ICMP_ADMIN_PROHIBITED = "icmp-admin-prohibited"
    TCP_RESET = "tcp-reset"
    ICMP6_NO_ROUTE = "icmp6-no-route"
    NO_ROUTE = "no-route"
    ICMP6_ADM_PROHIBITED = "icmp6-adm-prohibited"
    ADM_PROHIBITED = "adm-prohibited"
    ICMP6_ADDR_UNREACHABLE = "icmp6-addr-unreachable"
    ADDR_UNREACHABLE = "addr-unreach"
    ICMP6_PORT_UNREACHABLE = "icmp6-port-unreachable"
