from typing import Tuple

import pytest

from iptables.iptables import iptables, Flags
from iptables.enums import ConnbytesDirection, ConnbytesMode, Protocols, Tables, Chains, Actions


# test tables
@pytest.mark.parametrize('table', Tables, ids=lambda t: t.name.lower())
def test_tables(table: Tables):
    rule = iptables().check(Chains.INPUT).table(table).build()
    assert rule == f'iptables -4 -t {table.value} -C INPUT'


def test_table_twice():
    rule = iptables().check(Chains.INPUT).table(Tables.NAT).table(Tables.MANGLE).build()
    assert rule == 'iptables -4 -t mangle -C INPUT'


@pytest.mark.parametrize('chain', Chains, ids=lambda c: c.name.lower())
def test_chains(chain: Chains):
    explicit = iptables().chain(chain).action(Actions.CHECK).build()
    from_action_function = iptables().check(chain).build()
    assert explicit == from_action_function == f'iptables -4 -t filter -C {chain.value}'


def test_chain_twice():
    rule = iptables().check(Chains.INPUT).append(Chains.OUTPUT).build()
    assert rule == 'iptables -4 -t filter -A OUTPUT'


# test all action functions
@pytest.mark.parametrize('action', Actions, ids=lambda a: a.name.lower())
@pytest.mark.parametrize('chain', Chains, ids=lambda c: c.name.lower())
def test_action_functions(action: Actions, chain: Chains):
    rule = getattr(iptables(), action.name.lower())(chain).build()
    explicit = iptables().chain(chain).action(action).build()
    assert rule == explicit == f'iptables -4 -t filter {action.value} {chain.value}'


def test_action_function_twice():
    rule = iptables().check(Chains.INPUT).append(Chains.OUTPUT).build()
    assert rule == 'iptables -4 -t filter -A OUTPUT'


def test_ip_version():
    rule = iptables().check(Chains.INPUT).ipv4().build()
    assert rule == 'iptables -4 -t filter -C INPUT'

    rule = iptables().check(Chains.INPUT).ipv6().build()
    assert rule == 'iptables -6 -t filter -C INPUT'


def test_ip_version_twice():
    # TODO: should this raise an exception?
    rule = iptables().check(Chains.INPUT).ipv4().ipv6().build()
    assert rule == 'iptables -6 -t filter -C INPUT'

    rule = iptables().check(Chains.INPUT).ipv6().ipv4().build()
    assert rule == 'iptables -4 -t filter -C INPUT'


def test_protocol():
    rule = iptables().check(Chains.INPUT).protocol(Protocols.TCP).build()
    alias = iptables().check(Chains.INPUT).p(Protocols.TCP).build()
    assert rule == alias == 'iptables -4 -t filter -C INPUT -p tcp'

    rule = iptables().check(Chains.INPUT).protocol(Protocols.UDP).build()
    alias = iptables().check(Chains.INPUT).p(Protocols.UDP).build()
    assert rule == alias == 'iptables -4 -t filter -C INPUT -p udp'

    rule = iptables().check(Chains.INPUT).protocol(Protocols.ICMP).build()
    alias = iptables().check(Chains.INPUT).p(Protocols.ICMP).build()
    assert rule == alias == 'iptables -4 -t filter -C INPUT -p icmp'

    rule = iptables().check(Chains.INPUT).protocol(Protocols.ALL).build()
    alias = iptables().check(Chains.INPUT).p(Protocols.ALL).build()
    assert rule == alias == 'iptables -4 -t filter -C INPUT -p all'


def test_protocol_twice():
    rule = iptables().check(Chains.INPUT).protocol(Protocols.TCP).protocol(Protocols.UDP).build()
    assert rule == 'iptables -4 -t filter -C INPUT -p udp'


def test_fragment():
    rule = iptables().check(Chains.INPUT).fragment()
    assert rule.build() == 'iptables -f -4 -t filter -C INPUT'

    rule.fragment(False)
    assert rule.build() == 'iptables -4 -t filter -C INPUT'


def test_lock():
    rule = iptables().check(Chains.INPUT).lock()
    assert rule.build() == 'iptables -4 -w -t filter -C INPUT'

    rule.lock(False)
    assert rule.build() == 'iptables -4 -t filter -C INPUT'


def test_verbose():
    rule = iptables().check(Chains.INPUT).verbose()
    assert rule.build() == 'iptables -4 -v -t filter -C INPUT'

    rule.verbose(False)
    assert rule.build() == 'iptables -4 -t filter -C INPUT'


def test_resolve():
    rule = iptables().check(Chains.INPUT).resolve()
    assert rule.build() == 'iptables -4 -t filter -C INPUT'

    rule.resolve(False)
    assert rule.build() == 'iptables -4 -n -t filter -C INPUT'


def test_exact():
    rule = iptables().check(Chains.INPUT).exact()
    assert rule.build() == 'iptables -4 -x -t filter -C INPUT'

    rule.exact(False)
    assert rule.build() == 'iptables -4 -t filter -C INPUT'


def test_all_flags():
    rule = iptables().check(Chains.INPUT).fragment().lock().verbose().resolve(False).exact()
    assert rule.build() == 'iptables -f -4 -w -v -n -x -t filter -C INPUT'


def test_source():
    rule = iptables().check(Chains.INPUT).source('127.0.0.1', 8080).build()
    explicit = iptables().check(Chains.INPUT).source_host('127.0.0.1').source_port(8080).build()
    assert rule == explicit == 'iptables -4 -t filter -C INPUT -s 127.0.0.1 --sport 8080'


def test_source_host():
    rule = iptables().check(Chains.INPUT).source_host('127.0.0.1').build()
    alias = iptables().check(Chains.INPUT).src('127.0.0.1').build()
    short_alias = iptables().check(Chains.INPUT).s('127.0.0.1').build()
    assert rule == alias == short_alias == 'iptables -4 -t filter -C INPUT -s 127.0.0.1'


def test_source_port():
    rule = iptables().check(Chains.INPUT).source_port(8080).build()
    alias = iptables().check(Chains.INPUT).sport(8080).build()
    assert rule == alias == 'iptables -4 -t filter -C INPUT --sport 8080'


def test_destination():
    rule = iptables().check(Chains.INPUT).destination('127.0.0.1', 8080).build()
    explicit = iptables().check(Chains.INPUT).destination_host('127.0.0.1').destination_port(8080).build()
    assert rule == explicit == 'iptables -4 -t filter -C INPUT -d 127.0.0.1 --dport 8080'


def test_destination_host():
    rule = iptables().check(Chains.INPUT).destination_host('127.0.0.1').build()
    alias = iptables().check(Chains.INPUT).dst('127.0.0.1').build()
    short_alias = iptables().check(Chains.INPUT).d('127.0.0.1').build()
    assert rule == alias == short_alias == 'iptables -4 -t filter -C INPUT -d 127.0.0.1'


def test_destination_port():
    rule = iptables().check(Chains.INPUT).destination_port(8080).build()
    alias = iptables().check(Chains.INPUT).dport(8080).build()
    assert rule == alias == 'iptables -4 -t filter -C INPUT --dport 8080'


def test_in_interface():
    rule = iptables().check(Chains.INPUT).in_interface('eth0').build()
    alias = iptables().check(Chains.INPUT).i('eth0').build()
    assert rule == alias == 'iptables -4 -t filter -C INPUT -i eth0'


def test_out_interface():
    rule = iptables().check(Chains.INPUT).out_interface('eth0').build()
    alias = iptables().check(Chains.INPUT).o('eth0').build()
    assert rule == alias == 'iptables -4 -t filter -C INPUT -o eth0'


def test_comment():
    rule = iptables().check(Chains.INPUT).comment('test comment').build()
    assert rule == 'iptables -4 -t filter -C INPUT -m comment --comment "test comment"'


def test_connbytes():
    rule = iptables().check(Chains.INPUT).connbytes('0:0', mode=ConnbytesMode.BYTES, direction=ConnbytesDirection.BOTH).build()
    assert rule == ('iptables -4 -t filter -C INPUT -m connbytes --connbytes 0:0 --connbytes-mode bytes '
                    '--connbytes-dir both')
