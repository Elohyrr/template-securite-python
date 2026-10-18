import json
from unittest.mock import MagicMock

from src.tp1.utils.capture import Alert, AttackType
from src.tp1.utils.report import Report

PROTOCOLS = {"TCP": 50, "UDP": 20}


def make_capture() -> MagicMock:
    capture = MagicMock()
    capture.sort_network_protocols.return_value = PROTOCOLS
    return capture


def test_report_init():
    # Given
    capture = MagicMock()
    filename = "test.pdf"
    summary = "Test summary"

    # When
    report = Report(capture, filename, summary)

    # Then
    assert report.capture == capture
    assert report.filename == filename
    assert report.title == "Report Network Traffic Analysis"
    assert report.summary == summary
    assert report.array == []
    assert report.graph == ""


def test_save(tmp_path, monkeypatch):
    # Given
    monkeypatch.chdir(tmp_path)  # graph.png is written in the current directory
    report = Report(make_capture(), "test.pdf", "Test summary")

    # When
    report.save("test.pdf")

    # Then
    pdf = (tmp_path / "test.pdf").read_bytes()
    assert pdf.startswith(b"%PDF")


def test_generate_graph(tmp_path, monkeypatch):
    # Given
    monkeypatch.chdir(tmp_path)
    report = Report(make_capture(), "test.pdf", "Test summary")

    # When
    report.generate("graph")

    # Then
    assert report.graph == "\n![Graphique](graph.png)\n"
    assert (tmp_path / "graph.png").exists()


def test_generate_array():
    # Given
    report = Report(make_capture(), "test.pdf", "Test summary")

    # When
    report.generate("array")

    # Then
    assert report.array == [("Protocol", "Nb paquets"), ("TCP", "50"), ("UDP", "20")]


def test_generate_invalid_param():
    # Given
    report = Report(make_capture(), "test.pdf", "Test summary")

    # When
    report.generate("invalid")

    # Then
    assert report.graph == ""
    assert report.array == []


def test_generate_json(tmp_path):
    # Given
    capture = make_capture()
    capture.alerts = [
        Alert(AttackType.ARP_SPOOFING, "ARP", "192.168.1.1", "aa:bb:cc:dd:ee:ff", "arp"),
        Alert(AttackType.PORT_SCAN, "TCP", "10.0.0.5", "11:22:33:44:55:66", "scan"),
        Alert(AttackType.SQL_INJECTION, "TCP", "10.0.0.9", "66:55:44:33:22:11", "sql"),
    ]
    capture.flag = "ESGI{test}"
    report = Report(capture, "test.pdf", "Test summary")
    out_json = tmp_path / "report.json"

    # When
    report.generate_json(str(out_json))

    # Then
    assert json.loads(out_json.read_text()) == {
        "protocols": PROTOCOLS,
        "attacks": [
            {"type": "arp_spoofing", "attacker": "aa:bb:cc:dd:ee:ff"},
            {"type": "port_scan", "attacker": "10.0.0.5"},
            {"type": "sql_injection", "attacker": "10.0.0.9"},
        ],
        "flag": "ESGI{test}",
    }


def test_generate_json_without_flag(tmp_path):
    # Given
    capture = make_capture()
    capture.alerts = []
    capture.flag = None
    report = Report(capture, "test.pdf", "Test summary")
    out_json = tmp_path / "report.json"

    # When
    report.generate_json(str(out_json))

    # Then
    data = json.loads(out_json.read_text())
    assert data["attacks"] == []
    assert data["flag"] == ""
