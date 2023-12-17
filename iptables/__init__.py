from iptables.enums import ConnbytesDirection, ConnbytesMode, Protocols, Tables, Chains, Actions, TcpFlags, State, LimitUnits, RejectType
from iptables.exceptions import IPTablesError
from iptables.iptables import IPTablesRule


def iptables():
    return IPTablesRule()


__all__ = [
    "iptables",
    "IPTablesRule",
    "IPTablesError",
    "ConnbytesDirection",
    "ConnbytesMode",
    "Protocols",
    "Tables",
    "Chains",
    "Actions",
    "State",
    "TcpFlags",
    "RejectType",
    "LimitUnits"
]
