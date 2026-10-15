# from scapy.all import *

from tp1.utils.capture import Capture
from tp1.utils.config import logger
from tp1.utils.lib import parse_args


def main():
    logger.info("Starting TP1")

    args = parse_args()
    logger.info(args)

    capture = Capture()
    capture.capture_traffic(args.pcap, args.iface)
    capture.analyse("tcp")

    summary = capture.get_summary()
    logger.info(summary)

    # filename = "report.pdf"
    # report = Report(capture, filename, summary)
    # report.generate("graph")
    # report.generate("array")
    # report.save(filename)


if __name__ == "__main__":
    main()
