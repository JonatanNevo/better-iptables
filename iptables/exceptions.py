class IPTablesError(Exception):
    pass


class IPVersionError(IPTablesError):
    def __init__(self):
        super().__init__("ipv4 and ipv6 cannot be both True")


class ConnbytesError(IPTablesError):
    def __init__(self):
        super().__init__("connbytes must be in the format of 'bytes:bytes'")


class ConnlimitAddrError(IPTablesError):
    def __init__(self):
        super().__init__("saddr and daddr cannot be both True")


class MultiportSourceAndDestinationError(IPTablesError):
    def __init__(self):
        super().__init__("source_ports and destination_ports cannot be both True")


class MultiportPortsAndOtherError(IPTablesError):
    def __init__(self):
        super().__init__("ports cannot be used with source_ports or destination_ports")


class MultiportFormatError(IPTablesError):
    def __init__(self):
        super().__init__("ports must be an int or a string in format of 'port:port'")
