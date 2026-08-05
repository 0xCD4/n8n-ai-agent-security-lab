from __future__ import annotations

import argparse
import math
from pathlib import Path

from reportlab.lib.colors import HexColor
from reportlab.lib.pagesizes import portrait
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.pdfgen import canvas


PAGE_SIZE = portrait((504.0, 720.0))
W, H = PAGE_SIZE
M = 42

INK = HexColor("#111827")
MUTED = HexColor("#52606D")
BLUE = HexColor("#123A63")
BLUE_LIGHT = HexColor("#E8F0F7")
AMBER = HexColor("#9A5B12")
AMBER_LIGHT = HexColor("#F6E9D2")
GREEN = HexColor("#246B4A")
GREEN_LIGHT = HexColor("#E3F1E9")
RED = HexColor("#A33A2B")
RED_LIGHT = HexColor("#F7E3DF")
PAPER = HexColor("#F4F0E7")
WHITE = HexColor("#FFFFFF")
LINE = HexColor("#C8BEAD")
SLATE = HexColor("#E9ECEF")
PENCIL = HexColor("#756957")


def sketch_line(
    c: canvas.Canvas,
    x1: float,
    y1: float,
    x2: float,
    y2: float,
    color,
    *,
    width: float = 0.8,
    opacity: float = 0.28,
    seed: float = 0,
) -> None:
    dx = x2 - x1
    dy = y2 - y1
    length = math.hypot(dx, dy) or 1
    normal_x = -dy / length
    normal_y = dx / length
    wobble = math.sin(seed * 0.17 + 0.9) * 0.65
    offset = math.cos(seed * 0.11 + 0.4) * 0.35

    c.saveState()
    c.setStrokeColor(color)
    c.setStrokeAlpha(opacity)
    c.setLineWidth(width)
    c.setLineCap(1)
    path = c.beginPath()
    path.moveTo(x1 + normal_x * offset, y1 + normal_y * offset)
    path.lineTo(
        (x1 + x2) / 2 + normal_x * wobble,
        (y1 + y2) / 2 + normal_y * wobble,
    )
    path.lineTo(x2 - normal_x * offset, y2 - normal_y * offset)
    c.drawPath(path, fill=0, stroke=1)
    c.restoreState()


def paper_texture(c: canvas.Canvas, page_seed: int, *, light: bool = False) -> None:
    c.saveState()
    c.setStrokeColor(WHITE if light else PENCIL)
    c.setStrokeAlpha(0.055 if light else 0.045)
    c.setLineWidth(0.35)
    c.setLineCap(1)
    for index in range(48):
        x = 18 + ((index * 83 + page_seed * 29) % 468)
        y = 36 + ((index * 137 + page_seed * 47) % 648)
        length = 2.5 + ((index * 7 + page_seed) % 8)
        rise = (((index * 19 + page_seed * 3) % 9) - 4) * 0.12
        c.line(x, y, x + length, y + rise)
    c.restoreState()


def wrap(text: str, font: str, size: float, width: float) -> list[str]:
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = word if not current else f"{current} {word}"
        if stringWidth(candidate, font, size) <= width:
            current = candidate
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines


def text_block(
    c: canvas.Canvas,
    text: str,
    x: float,
    y: float,
    width: float,
    *,
    font: str = "Helvetica",
    size: float = 11,
    leading: float = 16,
    color=INK,
) -> float:
    c.setFont(font, size)
    c.setFillColor(color)
    for line in wrap(text, font, size, width):
        c.drawString(x, y, line)
        y -= leading
    return y


def label(c: canvas.Canvas, text: str, x: float, y: float, color=AMBER) -> None:
    c.setFillColor(color)
    c.setFont("Helvetica-Bold", 7.5)
    c.drawString(x, y, text.upper())


def title(c: canvas.Canvas, heading: str, x: float = M, y: float = 633, width: float = W - M * 2) -> float:
    c.setFillColor(INK)
    c.setFont("Times-Bold", 29)
    for line in wrap(heading, "Times-Bold", 29, width):
        c.drawString(x, y, line)
        y -= 33
    sketch_line(c, x, y + 20, x + 54, y + 19, AMBER, width=2.1, opacity=0.62, seed=x + y)
    return y


def rule(c: canvas.Canvas, y: float, x: float = M, width: float = W - M * 2) -> None:
    c.setStrokeColor(LINE)
    c.setLineWidth(0.8)
    c.line(x, y, x + width, y)


def page_base(c: canvas.Canvas, page: int, section: str, background=PAPER) -> None:
    c.setFillColor(background)
    c.rect(0, 0, W, H, fill=1, stroke=0)
    paper_texture(c, page, light=background == INK)
    c.setFillColor(BLUE)
    c.rect(0, H - 8, W, 8, fill=1, stroke=0)
    c.setFillColor(MUTED)
    c.setFont("Helvetica-Bold", 7.5)
    c.drawString(M, H - 30, "CSINT RESEARCH FIELD GUIDE 01")
    c.drawRightString(W - M, H - 30, section.upper())
    sketch_line(c, M, H - 38, M + 24, H - 38.5, AMBER, width=1.2, opacity=0.55, seed=page)
    c.setFillColor(MUTED)
    c.setFont("Helvetica", 8)
    c.drawString(M, 24, "BUILDING SAFER N8N SYSTEMS")
    c.drawRightString(W - M, 24, f"{page:02d}")


def rounded_panel(c: canvas.Canvas, x: float, y: float, w: float, h: float, fill=WHITE, stroke=LINE) -> None:
    c.setFillColor(fill)
    c.setStrokeColor(stroke)
    c.setLineWidth(0.9)
    c.roundRect(x, y, w, h, 7, fill=1, stroke=1)
    seed = x + y * 0.7 + w * 0.3 + h
    sketch_line(c, x + 8, y + h + 0.35, x + w - 10, y + h - 0.2, stroke, seed=seed)
    sketch_line(c, x + w + 0.25, y + h - 9, x + w - 0.25, y + 8, stroke, seed=seed + 1)
    sketch_line(c, x + w - 9, y - 0.25, x + 8, y + 0.3, stroke, seed=seed + 2)
    sketch_line(c, x - 0.2, y + 8, x + 0.25, y + h - 10, stroke, seed=seed + 3)


def node(
    c: canvas.Canvas,
    x: float,
    y: float,
    w: float,
    h: float,
    heading: str,
    body: str,
    *,
    fill=WHITE,
    stroke=BLUE,
) -> None:
    rounded_panel(c, x, y, w, h, fill=fill, stroke=stroke)
    label(c, heading, x + 12, y + h - 17, AMBER)
    text_block(c, body, x + 12, y + h - 37, w - 24, font="Helvetica-Bold", size=10, leading=12)


def arrow_path(c: canvas.Canvas, points: list[tuple[float, float]], color=BLUE) -> None:
    if len(points) < 2:
        raise ValueError("An arrow path needs at least two points")

    x1, y1 = points[-2]
    x2, y2 = points[-1]
    angle = math.atan2(y2 - y1, x2 - x1)
    head_length = 8.5
    head_half_width = 4.5
    base_x = x2 - math.cos(angle) * head_length
    base_y = y2 - math.sin(angle) * head_length
    normal_x = -math.sin(angle) * head_half_width
    normal_y = math.cos(angle) * head_half_width

    c.setStrokeColor(color)
    c.setFillColor(color)
    c.setLineWidth(2.4)
    c.setLineCap(1)
    c.setLineJoin(1)
    c.setDash()

    stem = c.beginPath()
    stem.moveTo(*points[0])
    for point in points[1:-1]:
        stem.lineTo(*point)
    stem.lineTo(base_x, base_y)
    c.drawPath(stem, fill=0, stroke=1)

    c.saveState()
    c.setStrokeColor(color)
    c.setStrokeAlpha(0.24)
    c.setLineWidth(0.75)
    c.setLineCap(1)
    c.setLineJoin(1)
    ink_trace = c.beginPath()
    for index, point in enumerate([*points[:-1], (base_x, base_y)]):
        jitter_x = math.sin((point[0] + point[1] + index * 13) * 0.09) * 0.45
        jitter_y = math.cos((point[0] - point[1] + index * 11) * 0.08) * 0.45
        if index == 0:
            ink_trace.moveTo(point[0] + jitter_x, point[1] + jitter_y)
        else:
            ink_trace.lineTo(point[0] + jitter_x, point[1] + jitter_y)
    c.drawPath(ink_trace, fill=0, stroke=1)
    c.restoreState()

    head = c.beginPath()
    head.moveTo(x2, y2)
    head.lineTo(base_x + normal_x, base_y + normal_y)
    head.lineTo(base_x - normal_x, base_y - normal_y)
    head.close()
    c.drawPath(head, fill=1, stroke=0)


def arrow(c: canvas.Canvas, x1: float, y1: float, x2: float, y2: float, color=BLUE) -> None:
    arrow_path(c, [(x1, y1), (x2, y2)], color)


def stat(c: canvas.Canvas, value: str, caption: str, x: float, y: float, w: float, color=BLUE) -> None:
    rounded_panel(c, x, y, w, 72, fill=WHITE, stroke=color)
    c.setFillColor(color)
    c.setFont("Times-Bold", 25)
    c.drawString(x + 12, y + 36, value)
    text_block(c, caption, x + 12, y + 20, w - 24, size=8.5, leading=11, color=MUTED)


def bullet_list(c: canvas.Canvas, items: list[str], x: float, y: float, width: float) -> float:
    for item in items:
        c.setFillColor(AMBER)
        c.circle(x + 3, y + 11, 2.2, fill=1, stroke=0)
        c.circle(x + 4.2, y + 11.7, 0.7, fill=1, stroke=0)
        y = text_block(c, item, x + 14, y + 8, width - 14, size=10.5, leading=15)
        y -= 7
    return y


def finish(c: canvas.Canvas) -> None:
    c.showPage()


def cover(c: canvas.Canvas) -> None:
    c.setFillColor(PAPER)
    c.rect(0, 0, W, H, fill=1, stroke=0)
    paper_texture(c, 1)
    c.setFillColor(BLUE)
    c.rect(0, H - 12, W, 12, fill=1, stroke=0)
    c.setStrokeColor(LINE)
    c.line(34, 0, 34, H)
    c.line(W - 34, 0, W - 34, H)
    label(c, "CSINT Research Field Guide 01", 52, 656, BLUE)
    c.setFillColor(INK)
    c.setFont("Times-Bold", 42)
    c.drawString(52, 564, "Building Safer")
    c.drawString(52, 518, "n8n Systems")
    sketch_line(c, 52, 498, 132, 496.5, AMBER, width=2.6, opacity=0.62, seed=52)
    text_block(c, "A plain English guide to review queues local security checks and human approval", 52, 476, 390, size=15, leading=21, color=MUTED)
    positions = [52, 170, 288, 406]
    node_width = 86
    names = [("INPUT", "Research\nqueue"), ("CONTROL", "Human\nreview"), ("EVIDENCE", "Security\nchecks"), ("RESULT", "Clear\ndecision")]
    for index, (x, (head, body)) in enumerate(zip(positions, names)):
        if index < 3:
            node(c, x, 285, node_width, 94, head, body.replace("\n", " "), fill=WHITE)
        else:
            c.setFillColor(BLUE)
            c.circle(x + 41, 332, 35, fill=1, stroke=0)
            c.setStrokeColor(WHITE)
            c.setLineWidth(4)
            c.line(x + 24, 332, x + 37, 319)
            c.line(x + 37, 319, x + 60, 347)
        if index < 3:
            target_x = positions[index + 1] - 6 if index < 2 else positions[index + 1] + 3
            arrow(c, x + node_width, 332, target_x, 332)
    rule(c, 222, 52, 400)
    text_block(c, "Static review. Runtime evidence. Clear limits.", 52, 190, 390, font="Helvetica-Bold", size=13, leading=18)
    label(c, "Ahmet Göker", 52, 82, BLUE)
    text_block(c, "CSINT Research", 52, 62, 200, size=10, color=MUTED)
    c.setFillColor(MUTED)
    c.setFont("Helvetica", 8)
    c.drawRightString(W - 52, 62, "2026")
    finish(c)


def page_2(c: canvas.Canvas) -> None:
    page_base(c, 2, "Start here")
    label(c, "A note before we begin", M, 656)
    y = title(c, "You do not need to be an n8n expert")
    y = text_block(c, "An n8n workflow is a set of small steps called nodes. Each node receives data or makes a choice or performs an action.", M, y - 8, 420, size=12, leading=18)
    y = text_block(c, "This book explains the systems I built. It focuses on why each part exists and where a person stays in control.", M, y - 12, 420, size=12, leading=18)
    rounded_panel(c, M, 148, 420, 245, fill=WHITE, stroke=BLUE)
    node(c, 70, 258, 104, 80, "NODE 01", "Receive a link", fill=BLUE_LIGHT)
    node(c, 200, 258, 104, 80, "NODE 02", "Check the item", fill=AMBER_LIGHT)
    node(c, 330, 258, 104, 80, "NODE 03", "Ask a person", fill=GREEN_LIGHT)
    arrow(c, 174, 298, 196, 298)
    arrow(c, 304, 298, 326, 298)
    label(c, "One useful question", 70, 220, BLUE)
    text_block(c, "Where can this input go?", 70, 193, 340, font="Times-Bold", size=20, leading=24)
    finish(c)


def page_3(c: canvas.Canvas) -> None:
    page_base(c, 3, "System map", BLUE_LIGHT)
    label(c, "The whole system", M, 656)
    y = title(c, "From a link to a clear decision")
    text_block(c, "The system has three layers. Each layer has one job.", M, y - 6, 420, size=12, leading=18)
    layers = [
        ("COLLECT", "Telegram or RSS", "Clean the URL and remove duplicates", 418, WHITE),
        ("REVIEW", "AI draft then human choice", "Keep the sheet as the source of truth", 286, AMBER_LIGHT),
        ("ACT", "GitHub issue or approved release", "Record what happened", 154, GREEN_LIGHT),
    ]
    for head, name, note, yy, fill in layers:
        rounded_panel(c, 72, yy, 360, 96, fill=fill, stroke=BLUE)
        label(c, head, 92, yy + 70, AMBER)
        text_block(c, name, 92, yy + 47, 310, font="Helvetica-Bold", size=13, leading=16)
        text_block(c, note, 92, yy + 24, 310, size=9.5, leading=13, color=MUTED)
    arrow(c, 252, 414, 252, 388)
    arrow(c, 252, 282, 252, 256)
    finish(c)


def page_4(c: canvas.Canvas) -> None:
    page_base(c, 4, "Research queue")
    label(c, "Chapter 01", M, 656)
    y = title(c, "The research queue")
    y = text_block(c, "The first workflow collects links from Telegram and RSS. It also accepts manual input.", M, y - 6, 420, size=12, leading=18)
    y = text_block(c, "Every URL is normalized. Duplicate links are removed. The result is stored in Google Sheets.", M, y - 10, 420, size=12, leading=18)
    stages = ["COLLECT", "CLEAN", "CHECK", "STORE"]
    captions = ["Telegram\nor RSS", "Normalize\nthe URL", "Remove\nduplicates", "Google\nSheets"]
    xs = [42, 154, 266, 378]
    node_width = 84
    for index, x in enumerate(xs):
        rounded_panel(c, x, 250, node_width, 112, fill=WHITE, stroke=BLUE if index != 2 else AMBER)
        label(c, stages[index], x + 11, 337, AMBER)
        text_block(c, captions[index].replace("\n", " "), x + 11, 310, node_width - 22, font="Helvetica-Bold", size=11, leading=15)
        if index < 3:
            arrow(c, x + node_width, 306, xs[index + 1] - 5, 306)
    rounded_panel(c, M, 140, 420, 70, fill=BLUE)
    c.setFillColor(WHITE)
    c.setFont("Times-Bold", 18)
    c.drawString(M + 18, 177, "The sheet stays the source of truth")
    text_block(c, "New. In review. Approved. Rejected. Published.", M + 18, 157, 380, size=9.5, leading=12, color=WHITE)
    finish(c)


def page_5(c: canvas.Canvas) -> None:
    page_base(c, 5, "Human review", AMBER_LIGHT)
    label(c, "Chapter 02", M, 656)
    y = title(c, "A person stays in the loop")
    text_block(c, "AI can suggest a category and a short draft. It cannot approve the item.", M, y - 8, 420, size=12, leading=18)
    rounded_panel(c, 62, 218, 380, 270, fill=WHITE, stroke=AMBER)
    label(c, "Telegram review card", 84, 457, AMBER)
    text_block(c, "One item needs your decision", 84, 425, 330, font="Times-Bold", size=20, leading=24)
    buttons = [("APPROVE", GREEN_LIGHT, GREEN), ("REJECT", RED_LIGHT, RED), ("ADD NOTE", BLUE_LIGHT, BLUE), ("LATER", SLATE, MUTED)]
    for index, (name, fill, stroke) in enumerate(buttons):
        yy = 354 - index * 42
        rounded_panel(c, 84, yy, 336, 32, fill=fill, stroke=stroke)
        c.setFillColor(stroke)
        c.setFont("Helvetica-Bold", 9)
        c.drawCentredString(252, yy + 11, name)
    label(c, "Rule", 62, 190, BLUE)
    text_block(c, "No public action happens before approval.", 62, 162, 380, font="Helvetica-Bold", size=14, leading=18)
    finish(c)


def page_6(c: canvas.Canvas) -> None:
    page_base(c, 6, "Owner relief")
    label(c, "Chapter 03", M, 656)
    y = title(c, "Less noise without losing control")
    text_block(c, "Pending messages are sorted into a small triage queue. One daily digest shows the most useful items.", M, y - 8, 420, size=12, leading=18)
    c.setFillColor(BLUE_LIGHT)
    c.circle(126, 318, 78, fill=1, stroke=0)
    c.setStrokeColor(BLUE)
    c.setLineWidth(5)
    c.circle(126, 318, 66, fill=0, stroke=1)
    c.line(126, 318, 126, 362)
    c.line(126, 318, 86, 318)
    label(c, "09:00", 104, 214, BLUE)
    rounded_panel(c, 236, 215, 220, 208, fill=WHITE, stroke=BLUE)
    label(c, "Daily digest", 256, 393, AMBER)
    bullet_list(c, ["New source ideas", "Risk requests", "Lab ideas", "Items waiting for approval"], 256, 355, 176)
    rounded_panel(c, 64, 122, 392, 54, fill=GREEN_LIGHT, stroke=GREEN)
    text_block(c, "Only the owner chat receives the digest.", 82, 151, 350, font="Helvetica-Bold", size=11, leading=14, color=GREEN)
    finish(c)


def page_7(c: canvas.Canvas) -> None:
    page_base(c, 7, "Work packets", BLUE_LIGHT)
    label(c, "Chapter 04", M, 656)
    y = title(c, "Approved work becomes a clear issue")
    text_block(c, "An approved queue row can become a GitHub issue. The issue includes context and safety limits and checks.", M, y - 8, 420, size=12, leading=18)
    node(c, 50, 312, 112, 94, "QUEUE", "Approved item", fill=WHITE)
    node(c, 196, 312, 112, 94, "GUARD", "Check for a duplicate", fill=AMBER_LIGHT)
    node(c, 342, 312, 112, 94, "GITHUB", "Create one issue", fill=GREEN_LIGHT)
    arrow(c, 162, 359, 191, 359)
    arrow(c, 308, 359, 337, 359)
    rounded_panel(c, 76, 171, 352, 92, fill=WHITE, stroke=BLUE)
    label(c, "Agent boundary", 96, 237, AMBER)
    text_block(c, "Prepare a change. Open a review. Do not publish or deploy.", 96, 211, 312, font="Helvetica-Bold", size=12, leading=17)
    finish(c)


def page_8(c: canvas.Canvas) -> None:
    page_base(c, 8, "Release approval", GREEN_LIGHT)
    label(c, "Chapter 05", M, 656)
    y = title(c, "Release notes start as drafts")
    text_block(c, "A local change is classified as major or minor or no share. Only useful changes move to a draft.", M, y - 8, 420, size=12, leading=18)
    node(c, 50, 330, 112, 88, "CHANGE", "Local update", fill=WHITE)
    node(c, 196, 330, 112, 88, "CHOICE", "Share level", fill=AMBER_LIGHT)
    node(c, 342, 330, 112, 88, "DRAFT", "Telegram card", fill=WHITE)
    arrow(c, 162, 374, 191, 374)
    arrow(c, 308, 374, 337, 374)
    arrow(c, 398, 325, 398, 286)
    rounded_panel(c, 314, 196, 168, 86, fill=GREEN_LIGHT, stroke=GREEN)
    label(c, "Approve", 332, 255, GREEN)
    text_block(c, "Send to the selected channel", 332, 230, 132, font="Helvetica-Bold", size=10.5, leading=14)
    rounded_panel(c, 22, 196, 238, 86, fill=RED_LIGHT, stroke=RED)
    label(c, "Edit or skip", 40, 255, RED)
    text_block(c, "No public post", 40, 226, 190, font="Helvetica-Bold", size=13, leading=16)
    arrow_path(c, [(252, 325), (252, 306), (141, 306), (141, 286)], RED)
    finish(c)


def page_9(c: canvas.Canvas) -> None:
    page_base(c, 9, "Risk path")
    label(c, "Chapter 06", M, 656)
    y = title(c, "Why workflow security came next")
    text_block(c, "A workflow can connect public input to a model. The model can reach a tool. The tool can reach a sensitive action.", M, y - 8, 420, size=12, leading=18)
    nodes = [("INPUT", "Public webhook", BLUE_LIGHT), ("AGENT", "AI agent", WHITE), ("TOOL", "External tool", AMBER_LIGHT), ("ACTION", "Sensitive write", RED_LIGHT)]
    xs = [34, 154, 274, 394]
    for index, (head, body, fill) in enumerate(nodes):
        node(c, xs[index], 300, 84, 92, head, body, fill=fill, stroke=RED if index == 3 else BLUE)
        if index < 3:
            arrow(c, xs[index] + 84, 346, xs[index + 1] - 5, 346, RED)
    rounded_panel(c, 110, 155, 284, 82, fill=BLUE, stroke=BLUE)
    c.setFillColor(WHITE)
    c.setFont("Times-Bold", 17)
    c.drawCentredString(252, 202, "Can untrusted input reach")
    c.drawCentredString(252, 180, "a powerful action without control?")
    finish(c)


def page_10(c: canvas.Canvas) -> None:
    page_base(c, 10, "Static review", BLUE_LIGHT)
    label(c, "Chapter 07", M, 656)
    y = title(c, "Read the export without running it")
    text_block(c, "The scanner treats an exported workflow as data. It follows visible paths between nodes. It never activates the workflow.", M, y - 8, 420, size=12, leading=18)
    stat(c, "10/100", "Unsafe example with nine findings", 42, 320, 196, RED)
    stat(c, "93/100", "Hardened example with one medium item", 266, 320, 196, GREEN)
    rounded_panel(c, 42, 174, 420, 104, fill=WHITE, stroke=BLUE)
    label(c, "Important", 62, 248, AMBER)
    text_block(c, "The score is a review aid. It is not proof that a workflow is secure.", 62, 222, 380, font="Helvetica-Bold", size=13, leading=18)
    finish(c)


def page_11(c: canvas.Canvas) -> None:
    page_base(c, 11, "Exposure graph")
    label(c, "Chapter 08", M, 656)
    y = title(c, "A graph turns findings into a path")
    text_block(c, "The graph keeps finding IDs on the edges. The same IDs appear in JSON and SARIF output.", M, y - 8, 420, size=12, leading=18)
    node(c, 42, 345, 96, 82, "START", "Webhook", fill=BLUE_LIGHT)
    node(c, 204, 345, 96, 82, "MODEL", "AI agent", fill=WHITE)
    node(c, 366, 345, 96, 82, "ACTION", "External write", fill=RED_LIGHT, stroke=RED)
    arrow(c, 138, 386, 199, 386, RED)
    arrow(c, 300, 386, 361, 386, RED)
    label(c, "AA-002", 157, 398, RED)
    label(c, "AA-004", 319, 398, RED)
    rounded_panel(c, 86, 167, 332, 118, fill=WHITE, stroke=LINE)
    label(c, "Findings ledger", 106, 257, AMBER)
    text_block(c, "AA-002  Public trigger needs review", 106, 229, 292, font="Helvetica-Bold", size=10.5, leading=15)
    text_block(c, "AA-004  Model path reaches a write action", 106, 200, 292, font="Helvetica-Bold", size=10.5, leading=15)
    finish(c)


def page_12(c: canvas.Canvas) -> None:
    page_base(c, 12, "Runtime gate", AMBER_LIGHT)
    label(c, "Chapter 09", M, 656)
    y = title(c, "Test behavior in an isolated target")
    text_block(c, "Static review shows what an export appears to allow. The runtime gate checks how a safe staging target responds.", M, y - 8, 420, size=12, leading=18)
    stat(c, "8/8", "Recorded scenarios passed", 42, 348, 126, GREEN)
    stat(c, "56/56", "Recorded checks passed", 189, 348, 126, BLUE)
    stat(c, "0", "External actions", 336, 348, 126, RED)
    rounded_panel(c, 42, 170, 420, 130, fill=WHITE, stroke=BLUE)
    label(c, "The gate checks", 62, 273, AMBER)
    bullet_list(c, ["Authentication and input shape", "Approval bypass and replay behavior", "Prompt injection containment around the workflow"], 62, 244, 380)
    finish(c)


def page_13(c: canvas.Canvas) -> None:
    page_base(c, 13, "Evidence receipt")
    label(c, "Chapter 10", M, 656)
    y = title(c, "Bind evidence to the exact candidate")
    text_block(c, "The receipt records a SHA-256 fingerprint. A change review accepts it only when the candidate fingerprint matches.", M, y - 8, 420, size=12, leading=18)
    node(c, 54, 350, 128, 90, "CANDIDATE", "Workflow export", fill=BLUE_LIGHT)
    node(c, 322, 350, 128, 90, "RECEIPT", "Staging record", fill=AMBER_LIGHT)
    rounded_panel(c, 168, 215, 168, 82, fill=GREEN_LIGHT, stroke=GREEN)
    label(c, "Exact match", 196, 270, GREEN)
    text_block(c, "Use as evidence", 196, 242, 112, font="Helvetica-Bold", size=12, leading=15, color=GREEN)
    arrow_path(c, [(118, 345), (118, 320), (210, 320), (210, 301)], BLUE)
    arrow_path(c, [(386, 345), (386, 320), (294, 320), (294, 301)], BLUE)
    label(c, "SHA-256", 228, 329, BLUE)
    text_block(c, "A receipt is a local record. It is not a signed attestation.", 74, 155, 356, font="Helvetica-Bold", size=11, leading=16)
    finish(c)


def page_14(c: canvas.Canvas) -> None:
    page_base(c, 14, "Change review", GREEN_LIGHT)
    label(c, "Chapter 11", M, 656)
    y = title(c, "Compare before release")
    text_block(c, "The change review compares a baseline with a candidate. It records what became safer and what needs more review.", M, y - 8, 420, size=12, leading=18)
    rounded_panel(c, 42, 250, 190, 208, fill=WHITE, stroke=BLUE)
    label(c, "Baseline", 62, 429, BLUE)
    bullet_list(c, ["Known findings", "Known controls", "Known destinations"], 62, 390, 150)
    rounded_panel(c, 272, 250, 190, 208, fill=WHITE, stroke=AMBER)
    label(c, "Candidate", 292, 429, AMBER)
    bullet_list(c, ["New or removed risk", "Stronger controls", "Credential type changes"], 292, 390, 150)
    arrow(c, 232, 354, 267, 354)
    rounded_panel(c, 108, 150, 288, 58, fill=BLUE, stroke=BLUE)
    text_block(c, "Approve only with clear evidence and known limits", 128, 184, 248, font="Helvetica-Bold", size=11, leading=14, color=WHITE)
    finish(c)


def page_15(c: canvas.Canvas) -> None:
    page_base(c, 15, "Workflow map", BLUE_LIGHT)
    label(c, "Chapter 12", M, 656)
    y = title(c, "One workflow can call another")
    text_block(c, "The map resolves calls between exported workflows when stable IDs are present. Unknown targets stay visible.", M, y - 8, 420, size=12, leading=18)
    node(c, 36, 354, 100, 84, "PUBLIC", "Intake flow", fill=WHITE)
    node(c, 202, 354, 100, 84, "ROUTER", "Calls a helper", fill=AMBER_LIGHT)
    node(c, 368, 354, 100, 84, "PRIVATE", "Write action", fill=RED_LIGHT, stroke=RED)
    arrow(c, 136, 396, 197, 396)
    arrow(c, 302, 396, 363, 396, RED)
    node(c, 202, 195, 132, 78, "UNKNOWN", "Unresolved target", fill=SLATE, stroke=MUTED)
    arrow(c, 252, 350, 252, 278, BLUE)
    rounded_panel(c, 54, 112, 396, 52, fill=WHITE, stroke=LINE)
    text_block(c, "Credential names become local aliases such as credential-01.", 72, 142, 360, font="Helvetica-Bold", size=10.5, leading=14)
    finish(c)


def page_16(c: canvas.Canvas) -> None:
    page_base(c, 16, "Public research")
    label(c, "Chapter 13", M, 656)
    y = title(c, "Research signals need a clear boundary")
    text_block(c, "The project scanned one hundred popular free AI Agent templates from the official n8n template API.", M, y - 8, 420, size=12, leading=18)
    stat(c, "100", "Templates scanned as JSON only", 42, 352, 126, BLUE)
    stat(c, "52", "Queued for path level review", 189, 352, 126, AMBER)
    stat(c, "0", "Templates imported or run", 336, 352, 126, GREEN)
    rounded_panel(c, 42, 174, 420, 120, fill=RED_LIGHT, stroke=RED)
    label(c, "Publication boundary", 62, 265, RED)
    text_block(c, "A scanner signal is not a confirmed vulnerability. High severity paths still need manual validation.", 62, 236, 380, font="Helvetica-Bold", size=13, leading=19, color=RED)
    finish(c)


def page_17(c: canvas.Canvas) -> None:
    page_base(c, 17, "Local first", GREEN_LIGHT)
    label(c, "Chapter 14", M, 656)
    y = title(c, "Keep sensitive workflow data local")
    text_block(c, "Workflow exports stay on the local machine during the scanner flow. The scanner does not send them to an AI API.", M, y - 8, 420, size=12, leading=18)
    layers = [
        ("LOCAL INPUT", "Redacted workflow export", 384, BLUE_LIGHT, BLUE),
        ("LOCAL REVIEW", "Static paths and report data", 282, WHITE, AMBER),
        ("SAFE OUTPUT", "Findings without prompt or credential values", 180, GREEN_LIGHT, GREEN),
    ]
    for head, body, yy, fill, stroke in layers:
        rounded_panel(c, 72, yy, 360, 72, fill=fill, stroke=stroke)
        label(c, head, 92, yy + 48, stroke)
        text_block(c, body, 92, yy + 25, 310, font="Helvetica-Bold", size=11, leading=14)
        if yy > 180:
            arrow(c, 252, yy - 4, 252, yy - 26, BLUE)
    text_block(c, "Remove secrets and customer data before you keep or share an export.", 72, 132, 360, font="Helvetica-Bold", size=11, leading=16, color=RED)
    finish(c)


def page_18(c: canvas.Canvas) -> None:
    page_base(c, 18, "Try the lab", INK)
    c.setFillColor(BLUE)
    c.rect(0, H - 8, W, 8, fill=1, stroke=0)
    c.setFillColor(HexColor("#B8C4D0"))
    c.setFont("Helvetica-Bold", 7.5)
    c.drawString(M, H - 30, "CSINT RESEARCH FIELD GUIDE 01")
    c.drawRightString(W - M, H - 30, "TRY THE LAB")
    label(c, "Chapter 15", M, 656, HexColor("#E9B45B"))
    c.setFillColor(WHITE)
    c.setFont("Times-Bold", 29)
    c.drawString(M, 610, "Four commands to start")
    text_block(c, "Use Node.js 20 or newer. No npm package installation is required.", M, 572, 420, size=12, leading=18, color=HexColor("#D5DEE7"))
    rounded_panel(c, 42, 215, 420, 300, fill=HexColor("#0B1220"), stroke=HexColor("#52606D"))
    commands = ["npm test", "npm run audit", "npm run gate:demo", "npm run map:demo"]
    yy = 458
    for index, command in enumerate(commands):
        c.setFillColor(HexColor("#6EE7B7"))
        c.setFont("Courier-Bold", 12)
        c.drawString(66, yy, f"$ {command}")
        c.setFillColor(HexColor("#52606D"))
        c.line(66, yy - 18, 438, yy - 18)
        yy -= 58
    text_block(c, "Use redacted files. Test only systems you own or are allowed to test.", 66, 250, 350, font="Helvetica-Bold", size=10.5, leading=15, color=HexColor("#F6C7BF"))
    c.setFillColor(HexColor("#B8C4D0"))
    c.setFont("Helvetica", 8)
    c.drawString(M, 24, "BUILDING SAFER N8N SYSTEMS")
    c.drawRightString(W - M, 24, "18")
    finish(c)


def page_19(c: canvas.Canvas) -> None:
    page_base(c, 19, "Lessons", AMBER_LIGHT)
    label(c, "What I learned", M, 656)
    y = title(c, "Simple systems are easier to trust")
    lessons = [
        ("ONE JOB", "Each step should have one clear purpose."),
        ("VISIBLE CONTROL", "Human approval should be easy to see."),
        ("EVIDENCE", "Safety checks should leave a useful record."),
        ("HONEST LIMITS", "Unknown facts should stay unknown."),
    ]
    yy = 462
    for index, (head, body) in enumerate(lessons):
        x = 42 if index % 2 == 0 else 260
        row_y = yy if index < 2 else 276
        rounded_panel(c, x, row_y, 202, 148, fill=WHITE, stroke=BLUE if index != 3 else AMBER)
        label(c, head, x + 18, row_y + 116, AMBER)
        text_block(c, body, x + 18, row_y + 82, 166, font="Times-Bold", size=16, leading=21)
    text_block(c, "The graph keeps bringing me back to one question.", 42, 192, 420, size=11, leading=16, color=MUTED)
    text_block(c, "Where can this input go?", 42, 154, 420, font="Times-Bold", size=24, leading=28, color=BLUE)
    finish(c)


def page_20(c: canvas.Canvas) -> None:
    page_base(c, 20, "Next steps", BLUE_LIGHT)
    label(c, "Road ahead", M, 656)
    y = title(c, "Build on the same small foundation")
    text_block(c, "The next direction is a safe import layer. It can review workflow files and community packages before installation.", M, y - 8, 420, size=12, leading=18)
    node(c, 42, 348, 116, 92, "WORKFLOW", "Static path review", fill=WHITE)
    node(c, 194, 348, 116, 92, "PACKAGE", "Community node review", fill=AMBER_LIGHT)
    node(c, 346, 348, 116, 92, "POLICY", "Allow or review or block", fill=GREEN_LIGHT)
    arrow(c, 158, 394, 189, 394)
    arrow(c, 310, 394, 341, 394)
    rounded_panel(c, 66, 204, 372, 90, fill=WHITE, stroke=LINE)
    label(c, "Not finished yet", 86, 268, RED)
    text_block(c, "This is a product direction. It is not a completed security guarantee.", 86, 240, 332, font="Helvetica-Bold", size=12, leading=17)
    text_block(c, "github.com/0xCD4/n8n-ai-agent-security-lab", 66, 144, 372, font="Courier-Bold", size=8.8, leading=12, color=BLUE)
    text_block(c, "en.csintresearch.org/n8n-systems-field-guide", 66, 124, 372, font="Courier-Bold", size=8.8, leading=12, color=BLUE)
    finish(c)


def build(output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    c = canvas.Canvas(str(output), pagesize=PAGE_SIZE)
    c.setTitle("Building Safer n8n Systems")
    c.setAuthor("Ahmet Göker")
    c.setSubject("A plain English field guide to n8n review queues and local workflow security checks")
    for render in [
        cover,
        page_2,
        page_3,
        page_4,
        page_5,
        page_6,
        page_7,
        page_8,
        page_9,
        page_10,
        page_11,
        page_12,
        page_13,
        page_14,
        page_15,
        page_16,
        page_17,
        page_18,
        page_19,
        page_20,
    ]:
        render(c)
    c.save()


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the n8n systems field guide PDF.")
    parser.add_argument("output", nargs="?", default="n8n-systems-field-guide.pdf")
    args = parser.parse_args()
    build(Path(args.output).resolve())


if __name__ == "__main__":
    main()
