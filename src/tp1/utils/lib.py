import argparse

from scapy.all import get_if_list

from tp1.utils.config import logger


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """
    Hello world function

    :return: "hello world"
    """
    parser = argparse.ArgumentParser(
        prog="tp1",
        description=(
            "Take interface or pcap file in input and analyse it "
            "to detect arp spoofing, port scan or sql injection."
        ),
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
    Display available network interfaces and let user choose one.

    :return: selected network interface name
    """
    interfaces = get_if_list()

    if not interfaces:
        logger.error("No network interfaces")
        return ""

    logger.info("Available network interfaces :")
    for i, interface in enumerate(interfaces, 1):
        logger.info(f"{i}. {interface}")

    while True:
        try:
            choice = input("Select an interface (number) : ").strip()
            choice_num = int(choice)

            if 1 <= choice_num <= len(interfaces):
                return interfaces[choice_num - 1]
            else:
                logger.warning(f"Invalid choice : enter a number between 1 and {len(interfaces)}")
        except ValueError:
            logger.warning("Invalid input : enter a valid number")
