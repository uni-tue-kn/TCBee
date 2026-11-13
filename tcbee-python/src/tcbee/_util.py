"""Shared validation and SQL identifier quoting."""

from ipaddress import ip_address


def integer(value, name, minimum=0):
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{name} must be an integer >= {minimum}")
    return value


def direction_code(value):
    try:
        return {"none": 0, "send": 1, "recv": 2}[value]
    except (KeyError, TypeError):
        raise ValueError("direction must be 'none', 'send' or 'recv'") from None


def address(value):
    ip = ip_address(value)
    # Match Rust's IpAddr::to_string(); Python < 3.13 prints mapped addresses in hex
    if getattr(ip, "ipv4_mapped", None) is not None:
        return f"::ffff:{ip.ipv4_mapped}"
    return str(ip)


def quote(name):
    if not isinstance(name, str) or not name or "\0" in name:
        raise ValueError("invalid SQL identifier in series catalog")
    return '"' + name.replace('"', '""') + '"'


def window(start_ns, end_ns):
    for value, name in ((start_ns, "start_ns"), (end_ns, "end_ns")):
        if value is not None:
            integer(value, name)
    if start_ns is not None and end_ns is not None and start_ns > end_ns:
        raise ValueError("start_ns must be <= end_ns")
