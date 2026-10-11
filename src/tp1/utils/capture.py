from scapy.all import rdpcap, sniff

from src.tp1.utils.lib import choose_interface
from tp1.utils.config import logger


class Capture:
    def __init__(self) -> None:
        self.interface = choose_interface()
        self.summary = ""
        self.packets = []

    def capture_traffic(self, pcap_file: str = "") -> None:
        """
        Capture network traffic from an interface
        (or read it from a pcap file if one is given)
        """
        interface = self.interface
        logger.info(f"Capture traffic from interface {interface}")

        if pcap_file:
            self.packets = rdpcap(pcap_file)
        else:
            self.packets = sniff(iface=interface, timeout=30)

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
        all_protocols = self.get_all_protocols()
        sort = self.sort_network_protocols()
        logger.debug(f"All protocols: {all_protocols}")
        logger.debug(f"Sorted protocols: {sort}")

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
        summary = ""
        return summary
