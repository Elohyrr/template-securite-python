import argparse

from scapy.all import get_if_list


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """
    Hello world function

    :return: "hello world"
    """
    parser = argparse.ArgumentParser(
        prog="tp1",
        description="Take interface or pcap file in input and analyse it to detect arp spoofing, port scan or sql injection.",
        epilog="This command generate a report in json and graph",
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--pcap", type=str, help="Path to the pcap file")
    group.add_argument("--iface", type=str, help="Network interface to capture traffic from")

    parser.add_argument(
        "--out", type=str, default="report.json", help="Output file name (default: report.json)"
    )

    return parser.parse_args(argv)


def choose_interface() -> str:
    """
    Return network interface and input user choice

    :return: network interface
    """
    int_list = get_if_list()
    interface = input(f"Choose an interface from the list {int_list}: ")
    return interface
