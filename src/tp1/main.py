# from scapy.all import *

from tp1.utils.capture import Capture
from tp1.utils.config import logger


def main():
    logger.info("Starting TP1")

    capture = Capture()
    capture.capture_traffic()
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
