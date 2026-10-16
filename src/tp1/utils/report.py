import pygal
from fpdf import FPDF
from pygal.style import DefaultStyle

from tp1.utils.capture import Capture


class Report:
    def __init__(self, capture: Capture, filename: str, summary: str):
        self.capture = capture
        self.filename = filename
        self.title = "TITRE DU RAPPORT"
        self.summary = summary
        self.array = ""
        self.graph = ""

    def concat_report(self) -> str:
        """
        Concatenate report content
        :return:
        """
        content = ""
        content += self.title
        content += self.summary
        content += self.array
        content += self.graph

        return content

    def save(self, filename: str) -> None:
        """
        Save report in a file
        :param filename:
        :return:
        """

        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("helvetica", "B", 20)

        # title
        pdf.cell(0, 15, self.title, align="C")
        pdf.ln(20)

        # summary
        pdf.set_font("helvetica", "B", 14)
        pdf.cell(0, 15, "Summary")
        pdf.ln(15)

        pdf.set_font("helvetica", "", 12)
        pdf.set_x(15)  # decale le summary
        pdf.multi_cell(w=180, h=8, text=self.summary)
        pdf.ln(10)

        # graph
        pdf.image("graph.png", x="C", w=170)

        pdf.output(filename)

    def generate(self, param: str) -> None:
        """
        Generate graph and array
        """
        sorted_protocol = self.capture.sort_network_protocols()

        if param == "graph":
            graph = pygal.Bar(title="Nombre de paquets par protocole", show_legend=False, print_values=True)
            graph.x_labels = list(sorted_protocol.keys())
            couleurs = DefaultStyle.colors
            graph.add(
                "",
                [
                    {"value": nombre, "color": couleurs[i % len(couleurs)]}
                    for i, nombre in enumerate(sorted_protocol.values())
                ],
            )
            graph.render_to_file("graph.svg")
            self.graph = "\n![Graphique](graph.svg)\n"

        elif param == "array":
            array = "┌──────────┬───────────┐\n"
            array += "│ Protocol │ Nb paquet │\n"
            array += "├──────────┼───────────┤\n"
            for nom, nombre in sorted_protocol.items():
                array += f"│   {nom:<6} │    {nombre:<6} │\n"
            array += "└──────────┴───────────┘"
            self.array = array
