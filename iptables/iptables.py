import dataclasses
import re
from enum import Enum
from typing import Optional, Union, List, Tuple
from typing_extensions import Self

from iptables.enums import ConnbytesDirection, ConnbytesMode, ConntrackStates, ConntrackStatus, ConntrackDirection, \
    LimitUnits, State, TcpFlags, Targets, Protocols, Tables, Chains, Actions, RejectType
from iptables.exceptions import IPTablesError, IPVersionError, ConnbytesError, ConnlimitAddrError, \
    MultiportSourceAndDestinationError, MultiportPortsAndOtherError, MultiportFormatError


@dataclasses.dataclass(frozen=True)
class Module:
    module: str
    parameters: List[Tuple[str, str]] = dataclasses.field(default_factory=list)

    def build(self) -> str:
        parameters = []
        for argument, value in self.parameters:
            if value:
                parameters.append(f"--{argument} {value}")
            else:
                parameters.append(f"--{argument}")
        return f"-m {self.module} {' '.join(parameters)}"


@dataclasses.dataclass(frozen=True)
class Flags:
    ipv4: bool = True
    ipv6: bool = False
    fragment: bool = False
    lock: bool = False  # same as --wait
    verbose: bool = False
    resolve: bool = True  # same as --numeric
    exact: bool = False

    def __post_init__(self) -> None:
        if self.ipv4 and self.ipv6:
            raise IPVersionError

    def build(self) -> str:
        flags = []
        if self.fragment:
            flags.append("-f")
        if self.ipv4:
            flags.append("-4")
        elif self.ipv6:
            flags.append("-6")
        if self.lock:
            flags.append("-w")
        if self.verbose:
            flags.append("-v")
        if not self.resolve:
            flags.append("-n")
        if self.exact:
            flags.append("-x")
        return " ".join(flags)

    def __str__(self) -> str:
        return self.build()


@dataclasses.dataclass(frozen=True)
class Matches:
    # TODO: add set-counters
    protocol: Optional[Protocols] = None
    source_host: Optional[str] = None
    source_port: Optional[int] = None
    destination_host: Optional[str] = None
    destination_port: Optional[int] = None
    in_interface: Optional[str] = None
    out_interface: Optional[str] = None

    def build(self) -> str:
        matches = []
        if self.protocol:
            matches.append(f"-p {self.protocol}")
        if self.source_host:
            matches.append(f"-s {self.source_host}")
        if self.source_port:
            matches.append(f"--sport {self.source_port}")
        if self.destination_host:
            matches.append(f"-d {self.destination_host}")
        if self.destination_port:
            matches.append(f"--dport {self.destination_port}")
        if self.in_interface:
            matches.append(f"-i {self.in_interface}")
        if self.out_interface:
            matches.append(f"-o {self.out_interface}")
        return " ".join(matches)

    def __str__(self) -> str:
        return self.build()

    def __bool__(self) -> bool:
        return any([self.protocol, self.source_host, self.source_port, self.destination_host, self.destination_port,
                    self.in_interface, self.out_interface])


@dataclasses.dataclass(frozen=True)
class Target:
    target: Targets
    parameters: List[Tuple[str, str]] = dataclasses.field(default_factory=list)

    def build(self) -> str:
        parameters = []
        for argument, value in self.parameters:
            if value:
                parameters.append(f"--{argument} {value}")
            else:
                parameters.append(f"--{argument}")
        if parameters:
            return f"-j {self.target} {' '.join(parameters)}"
        else:
            return f"-j {self.target}"

    def __str__(self) -> str:
        return self.build()


def _get_value(value: Union[Enum, str]) -> str:
    if isinstance(value, Enum):
        return value.value
    else:
        return value


class IPTablesRule:
    def __init__(
            self,
            *,
            table: Tables = Tables.FILTER,
            chain: Optional[Union[str, Chains]] = None,
            action: Optional[Actions] = None,
            target: Optional[Target] = None,
            flags: Flags = Flags(),
            matches: Matches = Matches(),
    ) -> None:
        self._table = table
        self._chain = chain
        self._action = action
        self._target = target
        self._flags = flags
        self._matches = matches

        self._modules = []

    # region base
    def table(self, table: Tables) -> Self:
        self._table = table
        return self

    def chain(self, chain: Union[str, Chains]) -> Self:
        self._chain = chain
        return self

    def action(self, action: Actions) -> Self:
        self._action = action
        return self

    def target(self, target: Target) -> Self:
        self._target = target
        return self

    # endregion

    # region actions
    def append(self, chain: Optional[Union[str, Chains]]) -> Self:
        self._action = Actions.APPEND
        if chain:
            self._chain = chain
        return self

    def delete(self, chain: Optional[Union[str, Chains]]) -> Self:
        self._action = Actions.DELETE
        if chain:
            self._chain = chain
        return self

    def insert(self, chain: Optional[Union[str, Chains]]) -> Self:
        self._action = Actions.INSERT
        if chain:
            self._chain = chain
        return self

    def replace(self, chain: Optional[Union[str, Chains]]) -> Self:
        self._action = Actions.REPLACE
        if chain:
            self._chain = chain
        return self

    def check(self, chain: Optional[Union[str, Chains]]) -> Self:
        self._action = Actions.CHECK
        if chain:
            self._chain = chain
        return self

    def list(self, chain: Optional[Union[str, Chains]]) -> Self:
        self._action = Actions.LIST
        if chain:
            self._chain = chain
        return self

    def flush(self, chain: Optional[Union[str, Chains]]) -> Self:
        self._action = Actions.FLUSH
        if chain:
            self._chain = chain
        return self

    def zero(self, chain: Optional[Union[str, Chains]]) -> Self:
        self._action = Actions.ZERO
        if chain:
            self._chain = chain
        return self

    def new_chain(self, chain: Optional[Union[str, Chains]]) -> Self:
        self._action = Actions.NEW_CHAIN
        if chain:
            self._chain = chain
        return self

    def delete_chain(self, chain: Optional[Union[str, Chains]]) -> Self:
        self._action = Actions.DELETE_CHAIN
        if chain:
            self._chain = chain
        return self

    def rename_chain(self, chain: Optional[Union[str, Chains]]) -> Self:
        self._action = Actions.RENAME_CHAIN
        if chain:
            self._chain = chain
        return self

    def policy(self, chain: Optional[Union[str, Chains]]) -> Self:
        self._action = Actions.POLICY
        if chain:
            self._chain = chain
        return self

    def list_rules(self, chain: Optional[Union[str, Chains]]) -> Self:
        self._action = Actions.LIST_RULES
        if chain:
            self._chain = chain
        return self

    # endregion

    # region flags
    def ipv4(self, enable: bool = True) -> Self:
        self._flags = dataclasses.replace(self._flags, ipv4=enable, ipv6=not enable)
        return self

    def ipv6(self, enable: bool = True) -> Self:
        self._flags = dataclasses.replace(self._flags, ipv6=enable, ipv4=not enable)
        return self

    def fragment(self, enable: bool = True) -> Self:
        self._flags = dataclasses.replace(self._flags, fragment=enable)
        return self

    def lock(self, enable: bool = True) -> Self:
        self._flags = dataclasses.replace(self._flags, lock=enable)
        return self

    def verbose(self, enable: bool = True) -> Self:
        self._flags = dataclasses.replace(self._flags, verbose=enable)
        return self

    def resolve(self, enable: bool = True) -> Self:
        self._flags = dataclasses.replace(self._flags, resolve=enable)
        return self

    def exact(self, enable: bool = True) -> Self:
        self._flags = dataclasses.replace(self._flags, exact=enable)
        return self

    # endregion

    # region matches
    def protocol(self, protocol: Protocols) -> Self:
        self._matches = dataclasses.replace(self._matches, protocol=protocol)
        return self

    def p(self, protocol: Protocols) -> Self:
        return self.protocol(protocol)

    def source(self, host: str, port: int) -> Self:
        self.source_host(host).source_port(port)
        return self

    def source_host(self, source_host: str) -> Self:
        self._matches = dataclasses.replace(self._matches, source_host=source_host)
        return self

    def src(self, source_host: str) -> Self:
        return self.source_host(source_host)

    def s(self, source_host: str) -> Self:
        return self.source_host(source_host)

    def source_port(self, source_port: int) -> Self:
        self._matches = dataclasses.replace(self._matches, source_port=source_port)
        return self

    def sport(self, source_port: int) -> Self:
        return self.source_port(source_port)

    def destination(self, host: str, port: int) -> Self:
        self.destination_host(host).destination_port(port)
        return self

    def destination_host(self, destination_host: str) -> Self:
        self._matches = dataclasses.replace(self._matches, destination_host=destination_host)
        return self

    def dst(self, destination_host: str) -> Self:
        return self.destination_host(destination_host)

    def d(self, destination_host: str) -> Self:
        return self.destination_host(destination_host)

    def destination_port(self, destination_port: int) -> Self:
        self._matches = dataclasses.replace(self._matches, destination_port=destination_port)
        return self

    def dport(self, destination_port: int) -> Self:
        return self.destination_port(destination_port)

    def in_interface(self, in_interface: str) -> Self:
        self._matches = dataclasses.replace(self._matches, in_interface=in_interface)
        return self

    def i(self, in_interface: str) -> Self:
        return self.in_interface(in_interface)

    def out_interface(self, out_interface: str) -> Self:
        self._matches = dataclasses.replace(self._matches, out_interface=out_interface)
        return self

    def o(self, out_interface: str) -> Self:
        return self.out_interface(out_interface)

    # endregion

    # region modules
    # TODO: missing: dccp, addrtype, ah, bpf, cgroup, cluster, devgroup, dscp, dst, ecn,
    #  esp, eui64, frag, hashlimit, hbh, helper, hl, icmp, icmp6, iprange, ipv6header, ipvs, length, mh, nfacct, osf,
    #  owner, physdev, pkttype, policty, qouta, rateest, realm, recent, rpfilter, rt, sctp, set, socket, statistics,
    #  tcpmss, time, tos, ttl, u32

    def comment(self, comment: str) -> Self:
        self._modules.append(Module(module="comment", parameters=[("comment", f'"{comment}"')]))
        return self

    def connbytes(self, connbytes: str, mode: ConnbytesMode, direction: ConnbytesDirection) -> Self:
        if not re.match("\d*:\d*", connbytes):
            raise ConnbytesError
        self._modules.append(Module(module="connbytes", parameters=[("connbytes", connbytes), ("connbytes-mode", mode),
                                                                    ("connbytes-dir", direction)]))
        return self

    def connlimit(
            self,
            upto: Optional[int] = None,
            above: Optional[int] = None,
            mask: Optional[int] = None,
            sadder: bool = True,
            daddr: bool = False
    ) -> Self:
        if sadder and daddr:
            raise ConnlimitAddrError
        parameters = []
        if upto:
            parameters.append(("connlimit-upto", str(upto)))
        if above:
            parameters.append(("connlimit-above", str(above)))
        if mask:
            parameters.append(("connlimit-mask", str(mask)))
        if sadder:
            parameters.append(("connlimit-saddr", None))
        if daddr:
            parameters.append(("connlimit-daddr", None))
        self._modules.append(Module(module="connlimit", parameters=parameters))
        return self

    def connmark(self, mark: int, mask: Optional[int] = None) -> Self:
        if mask:
            parameters = [("mark", f"{mark}/{mask}")]
        else:
            parameters = [("mark", mark)]
        self._modules.append(Module(module="connmark", parameters=parameters))
        return self

    def conntrack(
            self,
            *,
            state: Optional[List[ConntrackStates]] = None,
            status: Optional[List[ConntrackStatus]] = None,
            protocol: Optional[Protocols] = None,
            original_source: Optional[str] = None,
            original_source_port: Optional[int] = None,
            original_destination: Optional[str] = None,
            original_destination_port: Optional[int] = None,
            reply_source: Optional[str] = None,
            reply_source_port: Optional[int] = None,
            reply_destination: Optional[str] = None,
            reply_destination_port: Optional[int] = None,
            expire: Optional[int] = None,
            direction: Optional[ConntrackDirection] = None,
    ) -> Self:
        parameters = []
        if state:
            parameters.append(("ctstate", ",".join(state)))
        if status:
            parameters.append(("ctstatus", ",".join(status)))
        if protocol:
            parameters.append(("ctproto", protocol))
        if original_source:
            parameters.append(("ctorigsrc", original_source))
        if original_source_port:
            parameters.append(("ctorigsrcport", original_source_port))
        if original_destination:
            parameters.append(("ctorigdst", original_destination))
        if original_destination_port:
            parameters.append(("ctorigdstport", original_destination_port))
        if reply_source:
            parameters.append(("ctreplsrc", reply_source))
        if reply_source_port:
            parameters.append(("ctreplsrcport", reply_source_port))
        if reply_destination:
            parameters.append(("ctrepldst", reply_destination))
        if reply_destination_port:
            parameters.append(("ctrepldstport", reply_destination_port))
        if expire:
            parameters.append(("ctexpire", expire))
        if direction:
            parameters.append(("ctdir", direction))
        self._modules.append(Module(module="conntrack", parameters=parameters))
        return self

    def cpu(self, cpu: int) -> Self:
        self._modules.append(Module(module="cpu", parameters=[("cpu", str(cpu))]))
        return self

    def limit(self, rate: int = 3, units: LimitUnits = LimitUnits.HOUR, burst: int = 5) -> Self:
        self._modules.append(Module(module="limit", parameters=[("limit", f"{rate}/{units}"), ("limit-burst", burst)]))
        return self

    def mac(self, mac: str) -> Self:
        self._modules.append(Module(module="mac", parameters=[("mac-source", mac)]))
        return self

    def mark(self, mark: int, mask: Optional[int] = None) -> Self:
        if mask:
            parameters = [("mark", f"{mark}/{mask}")]
        else:
            parameters = [("mark", mark)]
        self._modules.append(Module(module="mark", parameters=parameters))
        return self

    def multiport(
            self,
            source_ports: Optional[List[Union[int, str]]] = None,
            destination_ports: Optional[List[Union[int, str]]] = None,
            ports: Optional[List[Union[int, str]]] = None
    ) -> Self:
        if source_ports and destination_ports:
            raise MultiportSourceAndDestinationError

        if ports and (source_ports or destination_ports):
            raise MultiportPortsAndOtherError

        for port_type, port_list in [("ports", ports), ("source-ports", source_ports),
                                     ("destination-ports", destination_ports)]:
            for port in port_list:
                if isinstance(port, str) and not re.match("\d*:\d*", port):
                    raise MultiportFormatError
            parameters = [(port_type, ",".join(port_list))]

        self._modules.append(Module(module="multiport", parameters=parameters))
        return self

    def state(self, state: State) -> Self:
        self._modules.append(Module(module="state", parameters=[("state", state)]))
        return self

    def tcp(
            self,
            syn: bool = False,
            option: Optional[int] = None,
            flags: Optional[Tuple[List[TcpFlags], List[TcpFlags]]] = None,
            source_port: Optional[Union[int, str]] = None,
            destination_port: Optional[Union[int, str]] = None
    ) -> Self:
        parameters = []
        if syn:
            parameters.append(("syn", None))
        if option:
            parameters.append(("tcp-option", option))
        if flags:
            mask, comp = flags
            mask_list = ",".join(mask)
            comp_list = ",".join(comp)
            parameters.append(("tcp-flags", f"{mask_list} {comp_list}"))
        if source_port:
            parameters.append(("source-port", source_port))
        if destination_port:
            parameters.append(("destination-port", destination_port))
        self._modules.append(Module(module="tcp", parameters=parameters))
        return self

    # endregion

    # region targets
    def accept(self) -> Self:
        self._target = Target(target=Targets.ACCEPT)
        return self

    def drop(self) -> Self:
        self._target = Target(target=Targets.DROP)
        return self

    def return_(self) -> Self:
        self._target = Target(target=Targets.RETURN)
        return self

    def reject(self, reject_type: Optional[Union[str, RejectType]] = None) -> Self:
        parameters = []
        if reject_type:
            parameters.append(("reject-with", reject_type))
        self._target = Target(target=Targets.REJECT, parameters=parameters)
        return self

    # endregion

    def build(self) -> str:
        output = ["iptables", self._flags.build()]
        if not self._table:
            raise IPTablesError("table is required")
        if not self._chain:
            raise IPTablesError("chain is required")
        if not self._action:
            raise IPTablesError("action is required")

        output.append(f"-t {_get_value(self._table)}")
        output.append(f"{_get_value(self._action)} {_get_value(self._chain)}")
        if self._matches:
            output.append(self._matches.build())
        for module in self._modules:
            output.append(module.build())
        if self._target:
            output.append(self._target.build())

        return " ".join(output)

    def __str__(self) -> str:
        return self.build()