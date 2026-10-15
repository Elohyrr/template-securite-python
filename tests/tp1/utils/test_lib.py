import argparse

import pytest

from src.tp1.utils.lib import choose_interface, parse_args


@pytest.mark.parametrize(
    "args, theoricalArgs",
    [
        ([], {"pcap": None, "iface": None, "out": "report.json"}),  # should return default values
        (
            ["--pcap", "filetest.pcap"],
            {"pcap": "filetest.pcap", "iface": None, "out": "report.json"},
        ),
        (
            ["--pcap", "filetest.pcap", "--iface", "eth0", "--out", "reporttest.json"],
            {"pcap": "filetest.pcap", "iface": "eth0", "out": "reporttest.json"},
        ),
    ],
    ids=["without_args", "with_pcap_arg", "with_all_args"],
)
def test_parse_args(args, theoricalArgs):
    # Given

    # When
    result = parse_args(args)

    # Then
    assert result == argparse.Namespace(**theoricalArgs)


def test_when_choose_interface_then_return_empty_string():
    # When
    result = choose_interface()

    # Then
    assert result == ""
