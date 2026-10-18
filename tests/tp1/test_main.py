import json
import sys

from scapy.all import ARP, IP, TCP, Ether, wrpcap

from src.tp1.main import main


def test_main_with_pcap_then_write_pdf_and_json(tmp_path, monkeypatch):
    # Given
    monkeypatch.chdir(tmp_path)  # graph.png is written in the current directory
    pcap = tmp_path / "capture.pcap"
    wrpcap(
        str(pcap),
        [
            Ether() / ARP(op=2, psrc="192.168.1.20", hwsrc="00:11:22:33:44:55"),
            Ether() / ARP(op=2, psrc="192.168.1.20", hwsrc="00:11:22:33:44:55"),
            Ether() / ARP(op=2, psrc="192.168.1.20", hwsrc="22:11:22:33:44:55"),
            Ether()
            / IP(src="192.168.1.67", dst="192.168.1.200")
            / TCP(sport=54148, dport=80)
            / b"GET /login.php?user=admin' OR 1=1--&token=ESGI{main} HTTP/1.1\r\n\r\n",
        ],
    )
    out = tmp_path / "result.json"
    monkeypatch.setattr(sys, "argv", ["tp1", "--pcap", str(pcap), "--out", str(out)])

    # When
    main()

    # Then
    data = json.loads(out.read_text())
    assert data["flag"] == "ESGI{main}"
    assert data["protocols"]["ARP"] == 3
    assert data["protocols"]["HTTP"] == 1
    assert {"type": "arp_spoofing", "attacker": "22:11:22:33:44:55"} in data["attacks"]
    assert {"type": "sql_injection", "attacker": "192.168.1.67"} in data["attacks"]
    assert (tmp_path / "result.pdf").read_bytes().startswith(b"%PDF")
