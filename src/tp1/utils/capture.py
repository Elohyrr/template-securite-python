import re
from dataclasses import dataclass
from urllib.parse import unquote

from scapy.all import ARP, IP, TCP, Ether, Raw, rdpcap, sniff

from tp1.utils.config import logger
from tp1.utils.lib import choose_interface, parse_args

THRESHOLD = 10
SQL_PATTERN = ["or 1=1", "union select", " or 1=1"]


class AttackType:
    ARP_SPOOFING = "ARP Spoofing"
    SQL_INJECTION = "SQL Injection"
    PORT_SCAN = "Port Scan"


@dataclass
class Alert:
    attack_type: AttackType
    protocol: str
    src_ip: str
    src_mac: str
    details: str


class Capture:
    def __init__(self) -> None:
        self.interface = ""
        self.summary = ""
        self.packets = []
        self.alerts: list[Alert] = []
        self.summary = ""
        self.flag = ""

    def capture_traffic(self) -> None:
        """
        Capture network traffic from an interface
        (or read it from a pcap file if one is given)
        """
        args = parse_args()
        logger.info(args)

        if args.pcap:
            pcap_file = args.pcap
            logger.info(f"Capture traffic from pcap file {pcap_file}")
            self.packets = rdpcap(pcap_file)
        elif args.iface:
            self.interface = args.iface
            logger.info(f"Capture traffic from interface {self.interface}")
            self.packets = sniff(iface=self.interface, timeout=30)
        else:
            self.interface = choose_interface()
            logger.info(f"Capture traffic from interface {self.interface}")
            self.packets = sniff(iface=self.interface, timeout=30)

        logger.info(f"{len(self.packets)} packets captured")

    def sort_network_protocols(self) -> dict:
        """
        Sort and return all captured network protocols
        """
        protocols = self.get_all_protocols()
        return dict(sorted(protocols.items(), key=lambda p: p[1], reverse=True))

    def get_all_protocols(self) -> dict:
        """
        Return all protocols captured with total packets number
        """
        protocols = {}
        for pkt in self.packets:
            for layer in pkt.layers():
                name = layer.__name__
                if name in ("Raw", "Padding"):
                    continue
                protocols[name] = protocols.get(name, 0) + 1
        return protocols

    def analyse(self, protocols: str) -> None:
        """
        Analyse all captured data and return statement
        Si un tra c est illégitime (exemple : Injection SQL, ARP
        Spoo ng, etc)
        a Noter la tentative d'attaque.
        b Relever le protocole ainsi que l'adresse réseau/physique
        de l'attaquant.
        c (FACULTATIF) Opérer le blocage de la machine
        attaquante.
        Sinon afficher que tout va bien
        """
        # all_protocols = self.get_all_protocols()
        # sort = self.sort_network_protocols()
        # logger.debug(f"All protocols: {all_protocols}")
        # logger.debug(f"Sorted protocols: {sort}")

        logger.info(f"Captured {len(self.packets)} packets")

        self.detect_arp_spoofing()
        self.detect_sql_injection()
        self.detect_port_scan()
        self.find_flag()

        self.summary = self._gen_summary()

    def get_summary(self) -> str:
        """
        Return summary
        :return:
        """
        return self.summary

    def _gen_summary(self) -> str:
        """
        Generate summary
        """
        if not self.alerts:
            return "No alerts detected."

        alerts_length = len(self.alerts)
        lines = [f"{alerts_length} alert(s) detected:"]
        for alert in self.alerts:
            lines.append(f"{alert.attack_type} : {alert.details}")
        return "\n".join(lines)

    def detect_arp_spoofing(self) -> None:
        """
        Detect ARP spoofing
        """
        logger.info("Detect ARP spoofing")
        pkts = self.packets
        ip_mac_mapping = {}
        for pkt in pkts:
            if not (pkt.haslayer(ARP) and pkt[ARP].op == 2):
                continue

            ip = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc
            if not (ip in ip_mac_mapping and ip_mac_mapping[ip] != mac):
                ip_mac_mapping[ip] = mac
                continue

            if (ip, mac) not in [(a.src_ip, a.src_mac) for a in self.alerts]:
                self.alerts.append(
                    Alert(
                        attack_type=AttackType.ARP_SPOOFING,
                        protocol="ARP",
                        src_ip=ip,
                        src_mac=mac,
                        details=f"IP {pkt[ARP].psrc} is being spoofed by MAC {mac}",
                    )
                )

    def detect_sql_injection(self) -> None:
        """
        Detect SQL injection
        """
        logger.info("Detect SQL injection")
        pkts = self.packets
        for pkt in pkts:
            if pkt.haslayer(Raw):
                texte = unquote(pkt[Raw].load.decode(errors="ignore")).lower()
                for motif in SQL_PATTERN:
                    if motif in texte:
                        self.alerts.append(
                            Alert(
                                attack_type=AttackType.SQL_INJECTION,
                                protocol="TCP",
                                src_ip=pkt[IP].src,
                                src_mac=pkt[Ether].src,
                                details=f"SQL injection attempt from {pkt[IP].src}",
                            )
                        )
                        break

    def detect_port_scan(self) -> None:
        """
        Detect PORT scan
        """
        logger.info("Detect PORT scan")

        pkts = self.packets
        ip_src_dst_port_couple = {}
        for pkt in pkts:
            if not (pkt.haslayer(TCP) and pkt[TCP].flags == "S"):
                continue

            pair = (pkt[IP].src, pkt[IP].dst)

            if pair not in ip_src_dst_port_couple:
                ip_src_dst_port_couple[pair] = []

            if pkt[TCP].dport not in ip_src_dst_port_couple[pair]:
                ip_src_dst_port_couple[pair].append(pkt[TCP].dport)

                if len(ip_src_dst_port_couple[pair]) == THRESHOLD:
                    self.alerts.append(
                        Alert(
                            attack_type=AttackType.PORT_SCAN,
                            protocol="TCP",
                            src_ip=pkt[IP].src,
                            src_mac="",
                            details=f"IP {pkt[IP].src} is scanning ports on IP {pkt[IP].dst}",
                        )
                    )

    def find_flag(self) -> None:
        """
        Find flag in captured packets
        """
        logger.info("Finding for flag....")
        pkts = self.packets

        for pkt in pkts:
            # if pkt.haslayer(TCP) and pkt[TCP].payload and b"GET /login" in bytes(pkt[TCP].payload):
            if pkt.haslayer(TCP) and pkt[TCP].payload:
                if not pkt.haslayer(Raw):
                    continue

                texte = unquote(pkt[Raw].load.decode(errors="ignore"))

                resultat = re.search(r"token=(ESGI\{[^}]+\})", texte)

                if resultat:
                    self.flag = resultat.group(1)
                    logger.info(f"Flag found: {self.flag}")
                    return
                else:
                    self.flag = None
        logger.info("No flag")
        # debug pkt.show()
        # # need to import regex instead of just 'get /login' and parse this packet b"GET /login.php?user=admin%27%20OR%201=1--%20&token=ESGI{tp1_47e333cd2508} HTTP/1.1\r\nHost: intranet\r\nUser-Agent: sqlmap/1.7\r\nX-Note: injection ' OR 1=1\r\n\r\n" like an idiot
        # regex on ESGI{tp1_47e333cd2508} to find the flag but be careful of fake flags !
        # wwill the flag be in other packet than raw ? dont think so but gonna test it
