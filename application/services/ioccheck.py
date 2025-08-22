import re

ipv6_regex = re.compile(
    r"""
^                                      # Start of string
(
    (?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}        |  # 1:1:1:1:1:1:1:1
    (?:[0-9a-fA-F]{1,4}:){1,7}:                     |  # 1::, 1:2:3:4:5:6:7::
    (?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}     |  # 1::8
    (?:[0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2} |
    (?:[0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3} |
    (?:[0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4} |
    (?:[0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5} |
    [0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4}){1,6}        |
    :((:[0-9a-fA-F]{1,4}){1,7}|:)                   |
    fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}   |
    ::(ffff(:0{1,4}){0,1}:)?                        # IPv4-mapped IPv6
    ((25[0-5]|2[0-4][0-9]|[01]?[0-9]{1,2})\.){3}
    (25[0-5]|2[0-4][0-9]|[01]?[0-9]{1,2})           |
    (?:[0-9a-fA-F]{1,4}:){1,4}:
    ((25[0-5]|2[0-4][0-9]|[01]?[0-9]{1,2})\.){3}
    (25[0-5]|2[0-4][0-9]|[01]?[0-9]{1,2})
)
$                                      # End of string
""",
    re.VERBOSE,
)


def ioc_type_finder(ioc: str) -> str:
    indicator = str(ioc)
    if re.match(r"[A-Fa-f0-9]{64}$", indicator):
        return "SHA256"
    if re.match(r"[A-Fa-f0-9]{32}$", indicator):
        return "MD5"
    if re.match(r"[A-Fa-f0-9]{40}$", indicator):
        return "SHA1"
    if re.match(
        r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
        indicator,
    ):
        return "IPv4"
    if re.match(ipv6_regex, indicator):
        return "IPv6"
    if re.match(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$", indicator):
        return "Domain"
    return "Domain"


def tenant_friendly_name(tenant_id: str) -> str:
    """Extract IOC from str"""
    match tenant_id:
        case "212e8b26-0a22-4ea9-b9e0-9c3dfb001559":
            return "WesHealth"
        case "32dfd67c-42d4-473b-8b85-ecf9779aa69f":
            return "WesHealthMA"
        case _:
            return None
