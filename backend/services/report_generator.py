import json
import os
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm, cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from sqlalchemy.orm import Session
from backend.models import Scan, AIAnalysis

REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "..", "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)


def generate_report(scan_id: int, db: Session) -> str:
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise ValueError(f"Scan {scan_id} not found")

    # Get AI analysis if available
    ai_analysis = db.query(AIAnalysis).filter(AIAnalysis.scan_id == scan_id).first()

    filename = f"ChainSentinel_Report_Scan{scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    filepath = os.path.join(REPORTS_DIR, filename)

    doc = SimpleDocTemplate(filepath, pagesize=A4,
                           topMargin=2*cm, bottomMargin=2*cm,
                           leftMargin=2*cm, rightMargin=2*cm)

    styles = getSampleStyleSheet()

    # Custom styles
    styles.add(ParagraphStyle(name='CoverTitle', fontSize=28, leading=34,
                              alignment=TA_CENTER, textColor=colors.HexColor('#1a1a2e'),
                              spaceAfter=10, fontName='Helvetica-Bold'))
    styles.add(ParagraphStyle(name='CoverSubtitle', fontSize=14, leading=18,
                              alignment=TA_CENTER, textColor=colors.HexColor('#16213e'),
                              spaceAfter=5))
    styles.add(ParagraphStyle(name='SectionTitle', fontSize=16, leading=20,
                              textColor=colors.HexColor('#0f3460'), spaceAfter=10,
                              spaceBefore=20, fontName='Helvetica-Bold'))
    styles.add(ParagraphStyle(name='SubSection', fontSize=12, leading=16,
                              textColor=colors.HexColor('#1a1a2e'), spaceAfter=6,
                              spaceBefore=10, fontName='Helvetica-Bold'))
    styles.add(ParagraphStyle(name='BodyText2', fontSize=10, leading=14,
                              alignment=TA_JUSTIFY, spaceAfter=6))
    styles.add(ParagraphStyle(name='SmallText', fontSize=8, leading=10,
                              textColor=colors.grey))

    elements = []

    # === COVER PAGE ===
    elements.append(Spacer(1, 4*cm))
    elements.append(Paragraph("ChainSentinel", styles['CoverTitle']))
    elements.append(Paragraph("Warehouse Security Test Report", styles['CoverSubtitle']))
    elements.append(Spacer(1, 1*cm))
    elements.append(HRFlowable(width="60%", thickness=2, color=colors.HexColor('#e94560')))
    elements.append(Spacer(1, 1*cm))

    cover_data = [
        ["Scan ID", f"#{scan.id}"],
        ["Scenario", scan.scenario.upper()],
        ["Target", f"{scan.target_host}:{scan.target_port}"],
        ["Status", scan.status],
        ["Started", str(scan.started_at or '-')[:19]],
        ["Completed", str(scan.completed_at or '-')[:19]],
        ["Total Findings", str(len(scan.findings))],
        ["Report Date", datetime.now().strftime("%d.%m.%Y %H:%M")],
    ]
    cover_table = Table(cover_data, colWidths=[4*cm, 11.5*cm])
    cover_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#0f3460')),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('LINEBELOW', (0, 0), (-1, -2), 0.5, colors.HexColor('#e0e0e0')),
    ]))
    elements.append(cover_table)
    elements.append(PageBreak())

    # === EXECUTIVE SUMMARY (if AI available) ===
    if ai_analysis and ai_analysis.executive_summary:
        elements.append(Paragraph("Executive Summary", styles['SectionTitle']))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e94560')))
        elements.append(Spacer(1, 0.5*cm))
        elements.append(Paragraph(ai_analysis.executive_summary, styles['BodyText2']))
        elements.append(Spacer(1, 0.5*cm))

    # === RISK ASSESSMENT (if AI available) ===
    if ai_analysis and ai_analysis.risk_summary:
        elements.append(Paragraph("Risk Assessment", styles['SectionTitle']))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e94560')))
        elements.append(Spacer(1, 0.5*cm))
        elements.append(Paragraph(ai_analysis.risk_summary, styles['BodyText2']))
        elements.append(Spacer(1, 0.5*cm))

    # === FINDINGS SUMMARY TABLE ===
    elements.append(Paragraph("Findings Summary", styles['SectionTitle']))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e94560')))
    elements.append(Spacer(1, 0.5*cm))

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in scan.findings:
        sev = f.severity.lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    severity_colors = {
        "critical": colors.HexColor('#dc3545'),
        "high": colors.HexColor('#fd7e14'),
        "medium": colors.HexColor('#ffc107'),
        "low": colors.HexColor('#28a745'),
    }

    summary_data = [["Severity", "Count"]]
    for sev, count in severity_counts.items():
        summary_data.append([sev.upper(), str(count)])
    summary_data.append(["TOTAL", str(len(scan.findings))])

    summary_table = Table(summary_data, colWidths=[5*cm, 3*cm])
    summary_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a1a2e')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (1, 0), (1, -1), 'CENTER'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e0e0e0')),
        ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
        ('BACKGROUND', (0, -1), (-1, -1), colors.HexColor('#f0f0f0')),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 0.5*cm))

    # === FINDINGS LIST TABLE ===
    if scan.findings:
        findings_data = [["#", "Finding", "Severity", "CVSS"]]
        for i, f in enumerate(scan.findings, 1):
            findings_data.append([
                str(i),
                Paragraph(f.title, ParagraphStyle('cell', fontSize=9, leading=11)),
                f.severity.upper(),
                str(f.cvss_score or '-')
            ])

        findings_table = Table(findings_data, colWidths=[1*cm, 9.5*cm, 2.5*cm, 2.5*cm])
        findings_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a1a2e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e0e0e0')),
            ('ALIGN', (0, 0), (0, -1), 'CENTER'),
            ('ALIGN', (2, 0), (3, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        elements.append(findings_table)

    elements.append(PageBreak())

    # === FINDING DETAILS ===
    elements.append(Paragraph("Finding Details", styles['SectionTitle']))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e94560')))
    elements.append(Spacer(1, 0.5*cm))

    for i, f in enumerate(scan.findings, 1):
        sev_color = severity_colors.get(f.severity.lower(), colors.grey)

        elements.append(Paragraph(f"{i}. {f.title}", styles['SubSection']))

        detail_data = [
            ["Severity", f.severity.upper()],
            ["Category", f.category],
            ["CVSS Score", str(f.cvss_score or '-')],
        ]
        detail_table = Table(detail_data, colWidths=[3*cm, 12*cm])
        detail_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(detail_table)

        if f.description:
            elements.append(Paragraph(f"<b>Description:</b> {f.description}", styles['BodyText2']))
        if f.evidence:
            evidence_text = f.evidence[:500].replace('\n', '<br/>').replace('<', '&lt;').replace('>', '&gt;').replace('&lt;br/&gt;', '<br/>')
            elements.append(Paragraph(f"<b>Evidence:</b><br/>{evidence_text}", styles['SmallText']))
        if f.remediation:
            elements.append(Paragraph(f"<b>Remediation:</b> {f.remediation}", styles['BodyText2']))

        elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#e0e0e0')))
        elements.append(Spacer(1, 0.3*cm))

    # === ATTACK CHAINS (if AI available) ===
    if ai_analysis and ai_analysis.attack_chains:
        elements.append(PageBreak())
        elements.append(Paragraph("Attack Chains", styles['SectionTitle']))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e94560')))
        elements.append(Spacer(1, 0.5*cm))

        try:
            chains = json.loads(ai_analysis.attack_chains)
            for chain in chains:
                elements.append(Paragraph(f"<b>{chain.get('name', '')}</b> [{chain.get('risk_level', '').upper()}]", styles['SubSection']))
                for j, step in enumerate(chain.get('steps', []), 1):
                    elements.append(Paragraph(f"  {j}. {step}", styles['BodyText2']))
                if chain.get('impact'):
                    elements.append(Paragraph(f"<b>Impact:</b> {chain['impact']}", styles['BodyText2']))
                elements.append(Spacer(1, 0.3*cm))
        except json.JSONDecodeError:
            pass

    # === MITRE ATT&CK (AI varsa) ===
    if ai_analysis and ai_analysis.mitre_mapping:
        elements.append(Paragraph("MITRE ATT&CK Mapping", styles['SectionTitle']))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e94560')))
        elements.append(Spacer(1, 0.5*cm))

        try:
            mappings = json.loads(ai_analysis.mitre_mapping)
            mitre_data = [["Finding", "Tactic", "Technique ID", "Technique"]]
            for m in mappings:
                mitre_data.append([
                    Paragraph(m.get('finding', ''), ParagraphStyle('cell', fontSize=8, leading=10)),
                    Paragraph(m.get('tactic', ''), ParagraphStyle('cell', fontSize=8, leading=10)),
                    m.get('technique_id', ''),
                    Paragraph(m.get('technique_name', ''), ParagraphStyle('cell', fontSize=8, leading=10))
                ])

            mitre_table = Table(mitre_data, colWidths=[4.5*cm, 3.5*cm, 2.5*cm, 5*cm])
            mitre_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a1a2e')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e0e0e0')),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            elements.append(mitre_table)
        except json.JSONDecodeError:
            pass

    # === PRIORITIZATION (if AI available) ===
    if ai_analysis and ai_analysis.prioritization:
        elements.append(Spacer(1, 0.5*cm))
        elements.append(Paragraph("Prioritization", styles['SectionTitle']))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e94560')))
        elements.append(Spacer(1, 0.5*cm))

        try:
            priorities = json.loads(ai_analysis.prioritization)
            for p in priorities:
                elements.append(Paragraph(f"<b>{p.get('priority', '')}. {p.get('finding', '')}</b>", styles['SubSection']))
                elements.append(Paragraph(p.get('reason', ''), styles['BodyText2']))
                elements.append(Spacer(1, 0.2*cm))
        except json.JSONDecodeError:
            pass

    # === FOOTER ===
    elements.append(Spacer(1, 1*cm))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#1a1a2e')))
    elements.append(Spacer(1, 0.3*cm))
    elements.append(Paragraph(f"This report was automatically generated by ChainSentinel on {datetime.now().strftime('%d.%m.%Y %H:%M')}.", styles['SmallText']))
    elements.append(Paragraph("ChainSentinel - Warehouse Security Testing Tool | chainsentinel.com", styles['SmallText']))

    doc.build(elements)
    return filepath
