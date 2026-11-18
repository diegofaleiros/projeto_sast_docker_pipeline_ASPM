#!/usr/bin/env python3
"""Gravador XLSX mínimo usando apenas a biblioteca padrão do Python.

Existe porque o ambiente não tem openpyxl/xlsxwriter e o `pip` está bloqueado por PEP 668
(ambiente externally-managed). Em vez de exigir venv ou rede, montamos o .xlsx à mão — ele
é só um ZIP com XML dentro (OOXML/SpreadsheetML).

Suporta o que um relatório de conformidade precisa: múltiplas abas, cabeçalho congelado,
autofiltro, largura de coluna, quebra de linha, tipos numéricos, hyperlink por fórmula e
alguns estilos de destaque por severidade.

DEFESA CONTRA INJEÇÃO DE FÓRMULA: texto vindo do repositório que comece com `=`, `+`, `-`
ou `@` seria executado pelo Excel/LibreOffice ao abrir o arquivo (CSV/formula injection).
Todo texto passa por `_defuse`, que prefixa apóstrofo. Uma planilha de segurança não pode
ser o vetor.
"""

from __future__ import annotations

import re
import zipfile
from typing import Any, Iterable, Sequence

MAX_CELL_CHARS = 32_767
MAX_SHEET_NAME = 31

# XML 1.0 não admite a maioria dos caracteres de controle; conteúdo de repositório os tem.
_ILLEGAL_XML = re.compile(
    "[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x84\x86-\x9f\ud800-\udfff﷐-﷟￾￿]"
)
_INVALID_SHEET_CHARS = re.compile(r"[\[\]\*/\\\?:]")

# Estilos (índices em cellXfs, na ordem em que styles.xml os declara)
S_DEFAULT = 0
S_HEADER = 1
S_WRAP = 2
S_CRITICAL = 3
S_HIGH = 4
S_MONO = 5
S_TITLE = 6
S_MUTED = 7
S_OK = 8


class Formula(str):
    """Marcador de fórmula CONFIÁVEL, gerada por este módulo.

    A distinção é por tipo, nunca por prefixo de texto: se `_cell_xml` decidisse "é fórmula
    porque começa com '='", qualquer descrição de regra ou caminho de arquivo vindo do
    repositório que começasse com `=HYPERLINK(` seria executado pelo Excel. Texto vindo de
    fora é sempre `str` e sempre passa por `_defuse`.
    """

    __slots__ = ()


def col_letter(index: int) -> str:
    """1 → A, 26 → Z, 27 → AA."""
    if index < 1:
        raise ValueError("índice de coluna começa em 1")
    out = ""
    while index > 0:
        index, rem = divmod(index - 1, 26)
        out = chr(65 + rem) + out
    return out


def _xml_escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _clean(value: Any) -> str:
    s = "" if value is None else str(value)
    s = _ILLEGAL_XML.sub("", s)
    if len(s) > MAX_CELL_CHARS:
        s = s[: MAX_CELL_CHARS - 1] + "…"
    return s


def _is_number(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, (int, float)):
        return True
    return False


def _defuse(text: str) -> str:
    """Neutraliza injeção de fórmula sem estragar texto legítimo."""
    if not text:
        return text
    if text[0] in ("=", "+", "@", "\t", "\r"):
        return "'" + text
    if text[0] == "-":
        try:  # "-42" é número, não fórmula
            float(text)
        except ValueError:
            return "'" + text
    return text


class Sheet:
    def __init__(
        self,
        name: str,
        headers: Sequence[str] | None = None,
        widths: Sequence[int] | None = None,
        freeze_header: bool = True,
        autofilter: bool = True,
    ):
        self.name = self._safe_name(name)
        self.headers = list(headers or [])
        self.widths = list(widths or [])
        self.freeze_header = freeze_header and bool(self.headers)
        self.autofilter = autofilter and bool(self.headers)
        self.rows: list[list[tuple[Any, int]]] = []
        self._header_offset = 0

    @staticmethod
    def _safe_name(name: str) -> str:
        n = _INVALID_SHEET_CHARS.sub("-", str(name)).strip("'")
        return (n[:MAX_SHEET_NAME] or "Planilha")

    def add_banner(self, text: str, style: int = S_TITLE) -> None:
        """Linha livre acima do cabeçalho (título, data de geração…)."""
        self.rows.append([(text, style)])
        self._header_offset += 1

    def add_row(self, values: Iterable[Any], style: int | Sequence[int] = S_DEFAULT) -> None:
        vals = list(values)
        if isinstance(style, int):
            styles = [style] * len(vals)
        else:
            styles = list(style) + [S_DEFAULT] * (len(vals) - len(style))
        self.rows.append([(v, styles[i]) for i, v in enumerate(vals)])

    # ------------------------------------------------------------------ serialização
    def _cell_xml(self, ref: str, value: Any, style: int) -> str:
        style_attr = f' s="{style}"' if style else ""
        if _is_number(value):
            return f'<c r="{ref}"{style_attr}><v>{value}</v></c>'
        is_formula = isinstance(value, Formula)
        text = _clean(value)
        if not text:
            return f'<c r="{ref}"{style_attr}/>'
        if is_formula and text.startswith("="):
            return f'<c r="{ref}"{style_attr}><f>{_xml_escape(text[1:])}</f></c>'
        text = _defuse(text)
        return f'<c r="{ref}"{style_attr} t="inlineStr"><is><t xml:space="preserve">{_xml_escape(text)}</t></is></c>'

    def to_xml(self) -> str:
        parts: list[str] = [
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
            '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">',
        ]

        header_row = self._header_offset + 1
        if self.freeze_header:
            top = f"A{header_row + 1}"
            parts.append(
                f'<sheetViews><sheetView workbookViewId="0" showGridLines="0">'
                f'<pane ySplit="{header_row}" topLeftCell="{top}" activePane="bottomLeft" state="frozen"/>'
                f"</sheetView></sheetViews>"
            )
        else:
            parts.append('<sheetViews><sheetView workbookViewId="0" showGridLines="0"/></sheetViews>')

        parts.append('<sheetFormatPr defaultRowHeight="15"/>')

        if self.widths:
            cols = "".join(
                f'<col min="{i}" max="{i}" width="{w}" customWidth="1"/>' for i, w in enumerate(self.widths, 1)
            )
            parts.append(f"<cols>{cols}</cols>")

        parts.append("<sheetData>")
        rownum = 0
        all_rows: list[list[tuple[Any, int]]] = list(self.rows)
        if self.headers:
            hdr = [(h, S_HEADER) for h in self.headers]
            all_rows.insert(self._header_offset, hdr)
        for row in all_rows:
            rownum += 1
            cells = "".join(
                self._cell_xml(f"{col_letter(i)}{rownum}", v, s) for i, (v, s) in enumerate(row, 1) if v is not None or s
            )
            parts.append(f'<row r="{rownum}">{cells}</row>')
        parts.append("</sheetData>")

        if self.autofilter and self.headers:
            last_col = col_letter(len(self.headers))
            last_row = max(rownum, header_row)
            parts.append(f'<autoFilter ref="A{header_row}:{last_col}{last_row}"/>')

        parts.append("</worksheet>")
        return "".join(parts)


_STYLES_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<fonts count="7">
<font><sz val="11"/><name val="Calibri"/></font>
<font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font>
<font><sz val="10"/><name val="Consolas"/></font>
<font><b/><sz val="14"/><name val="Calibri"/></font>
<font><sz val="10"/><color rgb="FF7F7F7F"/><name val="Calibri"/></font>
<font><b/><sz val="11"/><color rgb="FF7F1D1D"/><name val="Calibri"/></font>
<font><b/><sz val="11"/><color rgb="FF7C4A03"/><name val="Calibri"/></font>
</fonts>
<fills count="6">
<fill><patternFill patternType="none"/></fill>
<fill><patternFill patternType="gray125"/></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FF1F3864"/><bgColor indexed="64"/></patternFill></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FFF8CBCB"/><bgColor indexed="64"/></patternFill></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FFFDE4C0"/><bgColor indexed="64"/></patternFill></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FFD8F0DC"/><bgColor indexed="64"/></patternFill></fill>
</fills>
<borders count="2">
<border><left/><right/><top/><bottom/><diagonal/></border>
<border><left style="thin"><color rgb="FFBFBFBF"/></left><right style="thin"><color rgb="FFBFBFBF"/></right><top style="thin"><color rgb="FFBFBFBF"/></top><bottom style="thin"><color rgb="FFBFBFBF"/></bottom><diagonal/></border>
</borders>
<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
<cellXfs count="9">
<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1"><alignment vertical="top"/></xf>
<xf numFmtId="0" fontId="1" fillId="2" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment horizontal="left" vertical="center" wrapText="1"/></xf>
<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>
<xf numFmtId="0" fontId="5" fillId="3" borderId="0" xfId="0" applyFont="1" applyFill="1" applyAlignment="1"><alignment horizontal="center" vertical="top"/></xf>
<xf numFmtId="0" fontId="6" fillId="4" borderId="0" xfId="0" applyFont="1" applyFill="1" applyAlignment="1"><alignment horizontal="center" vertical="top"/></xf>
<xf numFmtId="0" fontId="2" fillId="0" borderId="0" xfId="0" applyFont="1" applyAlignment="1"><alignment vertical="top"/></xf>
<xf numFmtId="0" fontId="3" fillId="0" borderId="0" xfId="0" applyFont="1"/>
<xf numFmtId="0" fontId="4" fillId="0" borderId="0" xfId="0" applyFont="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>
<xf numFmtId="0" fontId="0" fillId="5" borderId="0" xfId="0" applyFill="1" applyAlignment="1"><alignment horizontal="center" vertical="top"/></xf>
</cellXfs>
<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>
</styleSheet>"""


def write_xlsx(path: str, sheets: Sequence[Sheet]) -> str:
    if not sheets:
        raise ValueError("é preciso ao menos uma aba")

    # Nomes de aba devem ser únicos, ou o Excel considera o arquivo corrompido.
    used: dict[str, int] = {}
    for sh in sheets:
        base = sh.name
        if base.lower() in used:
            used[base.lower()] += 1
            suffix = f"_{used[base.lower()]}"
            sh.name = base[: MAX_SHEET_NAME - len(suffix)] + suffix
        else:
            used[base.lower()] = 1

    n = len(sheets)
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
        + "".join(
            f'<Override PartName="/xl/worksheets/sheet{i}.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
            for i in range(1, n + 1)
        )
        + "</Types>"
    )

    root_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
        "</Relationships>"
    )

    workbook = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>'
        + "".join(
            f'<sheet name="{_xml_escape(sh.name)}" sheetId="{i}" r:id="rId{i}"/>'
            for i, sh in enumerate(sheets, 1)
        )
        + "</sheets></workbook>"
    )

    wb_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        + "".join(
            f'<Relationship Id="rId{i}" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
            f'Target="worksheets/sheet{i}.xml"/>'
            for i in range(1, n + 1)
        )
        + f'<Relationship Id="rId{n + 1}" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
        "</Relationships>"
    )

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", content_types)
        z.writestr("_rels/.rels", root_rels)
        z.writestr("xl/workbook.xml", workbook)
        z.writestr("xl/_rels/workbook.xml.rels", wb_rels)
        z.writestr("xl/styles.xml", _STYLES_XML)
        for i, sh in enumerate(sheets, 1):
            z.writestr(f"xl/worksheets/sheet{i}.xml", sh.to_xml())
    return path


def hyperlink(url: str, label: str) -> str | Formula:
    """Link por fórmula — evita ter de gerar rels por planilha.

    Só devolve `Formula` para http/https; qualquer outro esquema (`file:`, `javascript:`,
    `\\\\servidor\\share`) volta como texto inerte.
    """
    if not url or not str(url).startswith(("http://", "https://")):
        return str(label)
    u = str(url).replace('"', "").replace("\n", "").replace("\r", "")
    lb = str(label).replace('"', "'").replace("\n", " ")
    return Formula(f'=HYPERLINK("{u}","{lb}")')
