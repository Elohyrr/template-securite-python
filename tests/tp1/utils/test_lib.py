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
            ["--pcap", "filetest.pcap", "--out", "reporttest.json"],
            {"pcap": "filetest.pcap", "iface": None, "out": "reporttest.json"},
        ),
        (
            ["--iface", "eth0", "--out", "reporttest.json"],
            {"pcap": None, "iface": "eth0", "out": "reporttest.json"},
        ),
    ],
    ids=[
        "without_args",
        "with_pcap_arg",
        "with_pcap_and_out_args",
        "with_iface_and_out_args",
    ],
)
def test_parse_args(args, theoricalArgs):
    # Given

    # When
    result = parse_args(args)

    # Then
    assert result == argparse.Namespace(**theoricalArgs)


def test_parse_args_with_pcap_and_iface_then_exit():
    # Given

    # When

    # Then
    with pytest.raises(SystemExit):
        parse_args(["--pcap", "filetest.pcap", "--iface", "eth0"])


def test_when_choose_interface_then_return_empty_string(monkeypatch):  # if no interface found, return ""
    # Given
    monkeypatch.setattr("src.tp1.utils.lib.get_if_list", list)  # fake no interface found

    # When
    result = choose_interface()

    # Then
    assert result == ""
