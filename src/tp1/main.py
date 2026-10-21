from pathlib import Path

from tp1.utils.capture import Capture
from tp1.utils.config import logger
from tp1.utils.lib import parse_args
from tp1.utils.report import Report


def main():
    logger.info("Starting TP1")

    args = parse_args()
    logger.info(args)

    capture = Capture()
    capture.capture_traffic(args.pcap, args.iface)
    capture.analyse("tcp")

    summary = capture.get_summary()
    logger.info(summary)

    json_file = args.out
    pdf_file = str(Path(args.out).with_suffix(".pdf"))
    report = Report(capture, pdf_file, summary)
    report.generate("graph")
    report.generate("array")
    report.save(pdf_file)
    report.generate_json(json_file)
    logger.info(f"Report saved to {pdf_file} and {json_file}")


if __name__ == "__main__":
    main()
