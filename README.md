# Better iptables
A lean pythonic iptables parser and generator.  
Designed to work like the iptables cli.

```python
from iptables import iptables, Chains, Protocols, RejectType

# Create a new iptables rule using the iptables cli format
rule = iptables().append("INPUT").p("tcp").s('8.8.8.8').sport(22).reject("tcp-reset")

# Or create a new iptables rule using the pythonic format
iptables().append(Chains.INPUT).p(Protocols.TCP).source('8.8.8.8', 22).reject(RejectType.TCP_RESET)

# This will print the following:
# `iptables -4 -t filter -A INPUT -p tcp -s 8.8.8.8 --sport 22 -j REJECT --reject-with tcp-reset`
print(str(rule))
```

## Installation
__The package is not yet on pypi__
```bash
pip install better-iptables
```

## TODO:
- [ ] Add linters and formatters and mypy
- [ ] Add pre-commit
- [ ] Add CI/CD
  - [ ] Test all python versions 3.8 to 3.12
- [ ] Add rule parsing
- [ ] Finish supporting all modules
- [ ] Finish all unit tests
- [ ] Add integration tests that run against a real iptables instance and check validity of rules
- [ ] Implement a wrapper for the iptables python bindings `python-iptables`
- [ ] Add documentation
- [ ] QOL features
  - [ ] Allow to set multiports like ports: `iptables().source_ports([22, 23, 24])`
  - [ ] Check conflicting modules, for example `iptables().source_port(22).multiport(source_ports=[22, 23, 24])` should raise an exception