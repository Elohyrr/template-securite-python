import json

from fpdf import FPDF
from matplotlib.figure import Figure

from tp1.utils.capture import AttackType, Capture

COLORS = ["#EA6361", "#6A78C5", "#39AEA3", "#FFCF3B", "#FF7D54", "#B257C2", "#3CBCF6"]


class Report:
    def __init__(self, capture: Capture, filename: str, summary: str):
        self.capture = capture
        self.filename = filename
        self.title = "Report Network Traffic Analysis"
        self.summary = summary
        self.array = []
        self.graph = ""

    def save(self, filename: str) -> None:
        """
        Save report in a file
        :param filename:
        :return:
        """
        if not self.array:
            self.generate("array")
        if not self.graph:
            self.generate("graph")

        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("helvetica", "B", 20)

        # title
        pdf.cell(0, 15, self.title, align="C")
        pdf.ln(20)

        # summary
        pdf.set_font("helvetica", "B", 11)
        pdf.cell(0, 15, "Summary")
        pdf.ln(15)

        pdf.set_font("helvetica", "", 11)
        pdf.set_x(15)  # decale le summary
        pdf.multi_cell(w=0, h=6, text=self.summary)
        pdf.ln(10)

        # protocols table
        pdf.set_font("helvetica", "", 10)
        with pdf.table(width=140, text_align="CENTER") as table:
            for ligne in self.array:
                row = table.row()
                for valeur in ligne:
                    row.cell(valeur)

        pdf.ln(5)
        pdf.ln(5)

        # graph
        pdf.image("graph.png", x="C", w=150)
        pdf.ln(5)

        pdf.output(filename)

    def generate_json(self, out_json: str) -> None:
        """
        Generate the machine-readable report (protocols, attacks, flag)
        :param out_json:
        :return:
        """
        data = {
            "protocols": self.capture.sort_network_protocols(),
            "attacks": [
                {
                    "type": alert.attack_type.lower().replace(" ", "_"),
                    "attacker": alert.src_mac
                    if alert.attack_type == AttackType.ARP_SPOOFING
                    else alert.src_ip,
                }
                for alert in self.capture.alerts
            ],
            "flag": self.capture.flag or "",
        }
        with open(out_json, "w", encoding="utf-8") as report:
            json.dump(data, report, indent=4, ensure_ascii=False)

    def generate(self, param: str) -> None:
        """
        Generate graph and array
        """
        sorted_protocol = self.capture.sort_network_protocols()

        if param == "graph":
            figure = Figure(figsize=(8, 6))
            ax = figure.subplots()
            ax.bar(
                list(sorted_protocol.keys()),
                list(sorted_protocol.values()),
                color=[COLORS[i % len(COLORS)] for i in range(len(sorted_protocol))],
            )
            ax.set_title("Number of Packets per Network Protocol", fontsize=18)
            ax.tick_params(labelsize=14)
            ax.grid(axis="y", linestyle="--")
            ax.set_axisbelow(True)
            figure.savefig("graph.png", dpi=100)
            self.graph = "\n![Graphique](graph.png)\n"

        elif param == "array":
            self.array = [("Protocol", "Nb paquets")]
            for nom, nombre in sorted_protocol.items():
                self.array.append((nom, str(nombre)))
