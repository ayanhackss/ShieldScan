"""
PDF Report Generator - Creates branded scan reports.
Uses reportlab for PDF generation.
"""
import os, time, json

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib.colors import HexColor
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False


class ReportGenerator:
    __output_path = '/www/server/panel/plugin/malwarescan/reports'

    def __init__(self):
        os.makedirs(self.__output_path, exist_ok=True)

    def generate(self, scan_data):
        """Generate PDF report from scan data. Returns file path."""
        if not HAS_REPORTLAB:
            return {'status': False, 'msg': 'reportlab not installed'}

        scan_id = scan_data.get('scan_id', str(int(time.time())))
        filename = f"scan_report_{scan_id}.pdf"
        filepath = os.path.join(self.__output_path, filename)

        doc = SimpleDocTemplate(filepath, pagesize=A4,
                                leftMargin=20*mm, rightMargin=20*mm,
                                topMargin=20*mm, bottomMargin=20*mm)

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle('Title', parent=styles['Title'],
                                     fontSize=20, textColor=HexColor('#1a1a1a'))
        h2_style = ParagraphStyle('H2', parent=styles['Heading2'],
                                  fontSize=14, textColor=HexColor('#333333'),
                                  spaceAfter=8)
        body_style = ParagraphStyle('Body', parent=styles['Normal'],
                                    fontSize=10, textColor=HexColor('#444444'))
        mono_style = ParagraphStyle('Mono', parent=styles['Normal'],
                                    fontSize=8, fontName='Courier',
                                    textColor=HexColor('#555555'))

        elements = []

        # Header
        elements.append(Paragraph("Malware Scan Report", title_style))
        elements.append(Spacer(1, 5*mm))

        # Summary
        scan_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(scan_data.get('started', time.time())))
        threats = scan_data.get('threats', [])
        crit = len([t for t in threats if t.get('severity') == 'critical'])
        high = len([t for t in threats if t.get('severity') == 'high'])
        med = len([t for t in threats if t.get('severity') == 'medium'])

        summary_data = [
            ['Path Scanned', scan_data.get('path', 'N/A')],
            ['Scan Date', scan_time],
            ['Files Scanned', str(scan_data.get('total_files', 0))],
            ['Duration', f"{scan_data.get('elapsed', 0)}s"],
            ['Total Threats', str(len(threats))],
            ['Critical', str(crit)],
            ['High', str(high)],
            ['Medium', str(med)],
        ]

        elements.append(Paragraph("Summary", h2_style))
        t = Table(summary_data, colWidths=[45*mm, 120*mm])
        t.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('TEXTCOLOR', (0, 0), (-1, -1), HexColor('#333333')),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('LINEBELOW', (0, 0), (-1, -2), 0.5, HexColor('#eeeeee')),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 8*mm))

        # Verdict
        if not threats:
            elements.append(Paragraph("✓ No threats detected. Site appears clean.", body_style))
        else:
            elements.append(Paragraph(f"⚠ {len(threats)} threat(s) detected. Immediate action recommended.", body_style))

        elements.append(Spacer(1, 8*mm))

        # Threats table
        if threats:
            elements.append(Paragraph("Detected Threats", h2_style))

            threat_header = ['#', 'Severity', 'Category', 'File', 'Line', 'Description']
            threat_rows = [threat_header]

            for i, t in enumerate(threats[:100], 1):  # Limit to 100 in PDF
                fname = t.get('file', '').split('/')[-1] if t.get('file') else ''
                threat_rows.append([
                    str(i),
                    t.get('severity', '').upper(),
                    t.get('category', ''),
                    fname[:30],
                    str(t.get('line', '')),
                    t.get('description', '')[:50]
                ])

            col_widths = [8*mm, 18*mm, 22*mm, 45*mm, 12*mm, 60*mm]
            tt = Table(threat_rows, colWidths=col_widths, repeatRows=1)
            tt.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#f4f4f5')),
                ('TEXTCOLOR', (0, 0), (-1, -1), HexColor('#333333')),
                ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#e0e0e0')),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))

            # Color severity cells
            for i, t in enumerate(threats[:100], 1):
                if t.get('severity') == 'critical':
                    tt.setStyle(TableStyle([('TEXTCOLOR', (1, i), (1, i), HexColor('#dc2626'))]))
                elif t.get('severity') == 'high':
                    tt.setStyle(TableStyle([('TEXTCOLOR', (1, i), (1, i), HexColor('#ea580c'))]))

            elements.append(tt)

        # Footer
        elements.append(Spacer(1, 15*mm))
        elements.append(Paragraph(f"Generated by aaPanel Malware Scanner v1.0 — {scan_time}", mono_style))

        doc.build(elements)
        return {'status': True, 'path': filepath, 'filename': filename}

    def list_reports(self):
        reports = []
        for f in sorted(os.listdir(self.__output_path), reverse=True):
            if f.endswith('.pdf'):
                fpath = os.path.join(self.__output_path, f)
                reports.append({
                    'filename': f,
                    'size': os.path.getsize(fpath),
                    'created': int(os.path.getmtime(fpath))
                })
        return {'status': True, 'reports': reports}

    def delete_report(self, filename):
        fpath = os.path.join(self.__output_path, os.path.basename(filename))
        if os.path.exists(fpath):
            os.remove(fpath)
            return {'status': True, 'msg': 'Deleted'}
        return {'status': False, 'msg': 'Not found'}
