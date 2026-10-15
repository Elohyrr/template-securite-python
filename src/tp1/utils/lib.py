import argparse

from scapy.all import get_if_list


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """
    Hello world function

    :return: "hello world"
    """
    parser = argparse.ArgumentParser(
        prog="ProgramName", description="What the program does", epilog="Text at the bottom of help"
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
