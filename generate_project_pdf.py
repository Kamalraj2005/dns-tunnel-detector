"""
Script to generate a comprehensive, executive-grade PDF document containing:
- Live Deployed Streamlit Cloud URL Link
- Official GitHub Repository Link
- Complete GitHub README & Project Technical Documentation
- Zero-Trust MFA Credentials, Architecture & MITRE ATT&CK Mappings
"""

import os
import sys
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super(NumberedCanvas, self).__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super(NumberedCanvas, self).showPage()
        super(NumberedCanvas, self).save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))
        
        # Header (pages after page 1)
        if self._pageNumber > 1:
            self.drawString(54, 750, "DNS Armor | Incident Detection for DNS Tunneling Attacks — Official Project Dossier")
            self.setStrokeColor(colors.HexColor("#cbd5e1"))
            self.setLineWidth(0.5)
            self.line(54, 742, 558, 742)
            
        # Footer
        footer_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(558, 36, footer_text)
        self.drawString(54, 36, "CONFIDENTIAL — SOC Incident Response & Threat Hunting System")
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(54, 46, 558, 46)
        
        self.restoreState()


def create_project_pdf(output_path: str):
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )

    styles = getSampleStyleSheet()

    # Custom typography styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=22,
        leading=26,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=4
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=15,
        textColor=colors.HexColor("#0284c7"),
        spaceAfter=14
    )

    h1_style = ParagraphStyle(
        'Heading1_Custom',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=True
    )

    h2_style = ParagraphStyle(
        'Heading2_Custom',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=15,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=10,
        spaceAfter=4,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        'Body_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.2,
        leading=13.5,
        textColor=colors.HexColor("#334155"),
        spaceAfter=6
    )

    bullet_style = ParagraphStyle(
        'Bullet_Custom',
        parent=body_style,
        leftIndent=14,
        firstLineIndent=-10,
        spaceAfter=3
    )

    code_style = ParagraphStyle(
        'Code_Custom',
        parent=styles['Code'],
        fontName='Courier',
        fontSize=8.2,
        leading=11.5,
        textColor=colors.HexColor("#0f172a")
    )

    table_header_style = ParagraphStyle(
        'TH',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=11,
        textColor=colors.white
    )

    table_cell_style = ParagraphStyle(
        'TD',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.2,
        leading=11,
        textColor=colors.HexColor("#1e293b")
    )

    table_cell_bold = ParagraphStyle(
        'TDBold',
        parent=table_cell_style,
        fontName='Helvetica-Bold'
    )

    story = []

    # =========================================================================
    # COVER / HEADER BANNER
    # =========================================================================
    story.append(Paragraph("🛡️ DNS ARMOR: THREAT HUNTING PLATFORM", subtitle_style))
    story.append(Paragraph("Incident Detection for DNS Tunneling Attacks", title_style))
    story.append(Paragraph("Hybrid Information-Theoretic Entropy, Random Forest ML & Zero-Trust MFA SOC Console", ParagraphStyle(
        'MetaSubtitle', parent=body_style, fontName='Helvetica-Oblique', fontSize=10, leading=14, textColor=colors.HexColor("#475569")
    )))
    story.append(Spacer(1, 8))

    # Live Deployment & GitHub Quick Links Box
    links_data = [
        [
            Paragraph("<b>🌐 Live Streamlit Cloud Deployed URL:</b>", table_header_style),
            Paragraph("<font color='#00f0ff'><b><u>https://dns-tunnel-detector.streamlit.app</u></b></font>", table_header_style)
        ],
        [
            Paragraph("<b>🐙 Official GitHub Repository:</b>", table_cell_bold),
            Paragraph("<u>https://github.com/Kamalraj2005/dns-tunnel-detector</u>", table_cell_style)
        ],
        [
            Paragraph("<b>💻 Local / Intranet URL:</b>", table_cell_bold),
            Paragraph("http://localhost:8501", table_cell_style)
        ],
        [
            Paragraph("<b>👤 Author & Lead Engineer:</b>", table_cell_bold),
            Paragraph("Kamalraj Singh (singhkamalraj5@gmail.com)", table_cell_style)
        ],
        [
            Paragraph("<b>🔐 Regulatory Compliance:</b>", table_cell_bold),
            Paragraph("NIST SP 800-63B AAL2 &bull; PCI-DSS v4.0 Req 8.4 &bull; MITRE ATT&CK M1032", table_cell_style)
        ]
    ]

    t_links = Table(links_data, colWidths=[165, 339])
    t_links.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#f8fafc")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(t_links)
    story.append(Spacer(1, 14))

    # =========================================================================
    # 1. PROBLEM STATEMENT & MOTIVATION
    # =========================================================================
    story.append(Paragraph("1. Executive Summary & Threat Model", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#0284c7"), spaceAfter=8))
    
    story.append(Paragraph(
        "<b>The Vulnerability:</b> In modern computer network architectures, <b>UDP/TCP Port 53 (DNS)</b> is almost universally allowed "
        "outbound across enterprise firewalls to ensure uninterrupted domain resolution. Traditional Intrusion Prevention Systems (IPS) "
        "and Next-Gen Firewalls (NGFW) inspect packet headers but fail to evaluate information entropy and lexical characteristics of query subdomains. "
        "Adversaries exploit this blind spot to create bidirectional tunnels for covert command-and-control (C2) and exfiltrate sensitive enterprise data.",
        body_style
    ))
    story.append(Paragraph(
        "<b>Common Threat Vectors:</b> Tools like <code>iodine</code>, <code>dnscat2</code>, and Cobalt Strike DNS beacons fragment confidential files "
        "(passwords, database dumps, credit cards) into encoded subdomain strings. These queries bypass perimeter segmentation by relaying "
        "through recursive corporate resolvers to an attacker-controlled authoritative nameserver.",
        body_style
    ))
    story.append(Paragraph(
        "<b>Mission of DNS Armor:</b> This project delivers an end-to-end incident detection and response system that combines "
        "<b>Shannon Information Entropy</b>, an <b>18-feature Random Forest ML model</b>, automated session correlation, forensic payload reconstruction, "
        "and a <b>Zero-Trust Multi-Factor Authentication (MFA)</b> console.",
        body_style
    ))
    story.append(Spacer(1, 8))

    # =========================================================================
    # 2. ZERO-TRUST ACCESS CONTROL & MFA CREDENTIALS
    # =========================================================================
    story.append(Paragraph("2. Zero-Trust Identity & MFA Gateway (RFC 6238 TOTP)", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#0284c7"), spaceAfter=8))

    story.append(Paragraph(
        "To comply with <b>NIST SP 800-63B Authenticator Assurance Level 2 (AAL2)</b> and <b>PCI-DSS v4.0 Requirement 8.4</b>, "
        "access to operational telemetry and forensic reconstructor data is protected by a two-factor authentication gateway:",
        body_style
    ))
    story.append(Paragraph("&bull; <b>Factor 1 (Knowledge):</b> Primary operator credentials with Role-Based Access Control (RBAC).", bullet_style))
    story.append(Paragraph("&bull; <b>Factor 2 (Possession):</b> Cryptographic RFC 6238 Time-based One-Time Password (TOTP) supported by Google Authenticator, Microsoft Authenticator, and 1Password.", bullet_style))
    story.append(Paragraph("&bull; <b>Evaluator Quick-Pass:</b> A 1-click live dynamic OTP auto-fill button allows rapid viva testing without mobile scanning.", bullet_style))
    story.append(Spacer(1, 6))

    # Credentials Table
    mfa_table_data = [
        [
            Paragraph("Operator Identity", table_header_style),
            Paragraph("Assigned Role", table_header_style),
            Paragraph("Clearance Level", table_header_style),
            Paragraph("Login Username", table_header_style),
            Paragraph("Master Password", table_header_style),
            Paragraph("Base32 TOTP Secret", table_header_style)
        ],
        [
            Paragraph("<b>Alex Mercer</b>", table_cell_style),
            Paragraph("SOC Tier-2 Analyst", table_cell_style),
            Paragraph("RESTRICTED_INVESTIGATOR", code_style),
            Paragraph("analyst@soc.corp", code_style),
            Paragraph("CyberDefense@2026", code_style),
            Paragraph("JBSWY3DPEHPK3PXP", code_style)
        ],
        [
            Paragraph("<b>Dr. Sarah Chen</b>", table_cell_style),
            Paragraph("CISO / Red Team Admin", table_cell_style),
            Paragraph("FULL_COMMAND_AUTHORITY", code_style),
            Paragraph("admin@soc.corp", code_style),
            Paragraph("RootAdmin@2026", code_style),
            Paragraph("KRMUY4TFOJQXEZ3T", code_style)
        ]
    ]

    t_mfa = Table(mfa_table_data, colWidths=[75, 85, 110, 85, 75, 74])
    t_mfa.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor("#f1f5f9")),
        ('BACKGROUND', (0, 2), (-1, 2), colors.white),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(t_mfa)
    story.append(Spacer(1, 10))

    # =========================================================================
    # 3. SYSTEM ARCHITECTURE & DETECTION METHODOLOGY
    # =========================================================================
    story.append(Paragraph("3. System Architecture & Detection Pipeline", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#0284c7"), spaceAfter=8))

    story.append(Paragraph(
        "The architecture consists of five sequential processing layers operating with sub-millisecond per-query latency:",
        body_style
    ))

    arch_layers = [
        [
            Paragraph("Pipeline Stage", table_header_style),
            Paragraph("Component & Subsystem", table_header_style),
            Paragraph("Technical Specifications & Functions", table_header_style)
        ],
        [
            Paragraph("<b>Stage 1: Ingestion</b>", table_cell_style),
            Paragraph("PCAP Parser & Live Sniffer<br/><code>src/capture/</code>", table_cell_style),
            Paragraph("Reads offline <code>.pcap</code>/<code>.pcapng</code> captures via Scapy (with PcapNgReader fallback). Non-blocking live wire sniffing on UDP port 53 via Npcap driver.", table_cell_style)
        ],
        [
            Paragraph("<b>Stage 2: Features</b>", table_cell_style),
            Paragraph("Feature Extraction Engine<br/><code>src/features/</code>", table_cell_style),
            Paragraph("Computes Shannon Entropy H(X), RFC 1035 label lengths, hexadecimal/digit density, vowel ratios, and longest consonant runs across 18 numerical dimensions.", table_cell_style)
        ],
        [
            Paragraph("<b>Stage 3: Hybrid Engine</b>", table_cell_style),
            Paragraph("Rules + Random Forest ML<br/><code>src/detection/</code>", table_cell_style),
            Paragraph("Tier 1: 6 fast-path heuristic rules (entropy, oversized labels, covert TXT/NULL records).<br/>Tier 2: Supervised Random Forest Classifier (50 estimators, max depth 6).", table_cell_style)
        ],
        [
            Paragraph("<b>Stage 4: Forensics</b>", table_cell_style),
            Paragraph("Incident & Payload Decoder<br/><code>src/detection/incident_engine.py</code>", table_cell_style),
            Paragraph("Sessionizes queries by <code>(Client IP, Apex Domain)</code> over sliding windows. Reassembles and decrypts chunked Base64, Hexadecimal, and Base32 leaked payloads.", table_cell_style)
        ],
        [
            Paragraph("<b>Stage 5: SOC Console</b>", table_cell_style),
            Paragraph("Streamlit Cyber Dashboard<br/><code>dashboard/app.py</code>", table_cell_style),
            Paragraph("8 interactive glassmorphic operational tabs, radial threat score gauges, Plotly distributions, and CSV/JSON SIEM export facilities.", table_cell_style)
        ]
    ]

    t_arch = Table(arch_layers, colWidths=[90, 120, 294])
    t_arch.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 5),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(t_arch)
    story.append(Spacer(1, 10))

    # =========================================================================
    # 4. MATHEMATICAL FORMULATION
    # =========================================================================
    story.append(Paragraph("4. Mathematical Formulation & Shannon Entropy", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#0284c7"), spaceAfter=8))

    story.append(Paragraph(
        "<b>Shannon Information Entropy Formula:</b> Measures the unpredictability or density of encoded data within a domain string:",
        body_style
    ))
    story.append(Paragraph("<b>H(X) = - &Sigma; P(x_i) &times; log<sub>2</sub> P(x_i)</b>", ParagraphStyle(
        'Formula', parent=body_style, fontName='Helvetica-Bold', fontSize=10, textColor=colors.HexColor("#0f172a"), leftIndent=20
    )))
    story.append(Paragraph(
        "&bull; <b>Natural Language / Benign Domains:</b> 2.0 &le; H(X) &le; 3.2 (e.g., <code>mail.google.com</code>, <code>api.github.com</code>).<br/>"
        "&bull; <b>Tunneling / Encrypted Payloads:</b> 3.85 &le; H(X) &le; 4.8+ (e.g., <code>b64-dGhpcyBpcyBhIHNlY3Jld...</code>).",
        body_style
    ))
    story.append(Paragraph(
        "<b>Composite Threat Score Formulation:</b><br/>"
        "<b>Query Score</b> = (Heuristic Score &times; 0.45) + (ML Probability &times; 100 &times; 0.55)<br/>"
        "<b>Session Incident Threat Score</b> = min(100, (Mean Query Threat &times; 0.65) + (Behavioral Score &times; 0.35))",
        body_style
    ))
    story.append(Spacer(1, 10))

    # =========================================================================
    # 5. CONSOLE OPERATIONAL TABS (8 TABS)
    # =========================================================================
    story.append(Paragraph("5. The 8 Operational Dashboard Tabs", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#0284c7"), spaceAfter=8))

    tabs_data = [
        [
            Paragraph("Tab # & Name", table_header_style),
            Paragraph("Core Functionality & Analyst Value", table_header_style)
        ],
        [
            Paragraph("<b>Tab 1: 🚨 Security Incidents</b>", table_cell_style),
            Paragraph("Correlated session cards, radial threat gauges (0-100), MITRE tags, triggered heuristics, and raw query drill-downs.", table_cell_style)
        ],
        [
            Paragraph("<b>Tab 2: 🕵️ Exfiltration Forensics</b>", table_cell_style),
            Paragraph("Automated reassembly of chunked Base64, Hexadecimal, and Base32 data leaks into plain-text recovered files and passwords.", table_cell_style)
        ],
        [
            Paragraph("<b>Tab 3: 📈 Telemetry & Profiling</b>", table_cell_style),
            Paragraph("Interactive Plotly histograms of Shannon Entropy, Query Length vs Entropy scatter plots, and temporal query velocity.", table_cell_style)
        ],
        [
            Paragraph("<b>Tab 4: ⚡ Live Domain Inspector</b>", table_cell_style),
            Paragraph("Instant analysis sandbox allowing analysts to type any custom FQDN and compute live entropy, 18 lexical metrics, and ML verdict.", table_cell_style)
        ],
        [
            Paragraph("<b>Tab 5: 🧠 AI Engine & Rules</b>", table_cell_style),
            Paragraph("Supervised Random Forest global feature importance rankings explaining exact mathematical weights behind threat decisions.", table_cell_style)
        ],
        [
            Paragraph("<b>Tab 6: 📋 Query Stream & Export</b>", table_cell_style),
            Paragraph("Searchable live query audit log with 1-click export to CSV and JSON formats for Splunk, Microsoft Sentinel, and SOAR pipelines.", table_cell_style)
        ],
        [
            Paragraph("<b>Tab 7: 🧪 Red Team Attack Lab</b>", table_cell_style),
            Paragraph("In-app attack simulation playground to craft custom confidential payloads and fire real UDP packets on port 53 to test sensors.", table_cell_style)
        ],
        [
            Paragraph("<b>Tab 8: 🔐 Zero-Trust Identity & MFA</b>", table_cell_style),
            Paragraph("Live authenticator device clock health, TOTP synchronization timer, operator access logs, and compliance matrix verification.", table_cell_style)
        ]
    ]

    t_tabs = Table(tabs_data, colWidths=[150, 354])
    t_tabs.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0, 0), (-1, -1), 3.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3.5),
        ('LEFTPADDING', (0, 0), (-1, -1), 5),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(t_tabs)
    story.append(Spacer(1, 10))

    # =========================================================================
    # 6. MITRE ATT&CK MAPPINGS & STANDARDS
    # =========================================================================
    story.append(Paragraph("6. MITRE ATT&CK® Alignment & Enterprise Compliance", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#0284c7"), spaceAfter=8))

    mitre_data = [
        [
            Paragraph("Technique ID", table_header_style),
            Paragraph("Technique Name", table_header_style),
            Paragraph("Tactic", table_header_style),
            Paragraph("SOC Detection Logic", table_header_style)
        ],
        [
            Paragraph("<b>T1071.004</b>", code_style),
            Paragraph("Application Layer Protocol: DNS", table_cell_style),
            Paragraph("Command & Control", table_cell_style),
            Paragraph("Periodic beaconing and bidirectional TXT/NULL record query abuse.", table_cell_style)
        ],
        [
            Paragraph("<b>T1048.003</b>", code_style),
            Paragraph("Exfiltration Over Alternative Protocol: DNS", table_cell_style),
            Paragraph("Exfiltration", table_cell_style),
            Paragraph("High-volume chunked Base64/Hex exfiltration payloads in subdomains.", table_cell_style)
        ],
        [
            Paragraph("<b>T1568.002</b>", code_style),
            Paragraph("Dynamic Resolution: DGA", table_cell_style),
            Paragraph("Defense Evasion", table_cell_style),
            Paragraph("High ratio of single-use randomized subdomains generated to evade caching.", table_cell_style)
        ]
    ]

    t_mitre = Table(mitre_data, colWidths=[70, 145, 95, 194])
    t_mitre.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0, 0), (-1, -1), 3.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3.5),
        ('LEFTPADDING', (0, 0), (-1, -1), 5),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(t_mitre)
    story.append(Spacer(1, 10))

    # =========================================================================
    # 7. ONE-CLICK RUN COMMANDS & SCRIPTS
    # =========================================================================
    story.append(Paragraph("7. Local Launchers & Automated Tools (Windows)", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#0284c7"), spaceAfter=8))

    launch_data = [
        [
            Paragraph("Feature / Tool", table_header_style),
            Paragraph("One-Click Batch Script", table_header_style),
            Paragraph("Manual PowerShell Command", table_header_style)
        ],
        [
            Paragraph("<b>🌐 SOC Web Dashboard</b>", table_cell_style),
            Paragraph("<code>run_dashboard.bat</code>", code_style),
            Paragraph("<code>.\\.venv\\Scripts\\streamlit.exe run dashboard/app.py</code>", code_style)
        ],
        [
            Paragraph("<b>📡 Real-Time Wire Sniffer</b>", table_cell_style),
            Paragraph("<code>run_live_monitor.bat</code>", code_style),
            Paragraph("<code>.\\.venv\\Scripts\\python.exe live_monitor.py</code>", code_style)
        ],
        [
            Paragraph("<b>⚡ Live Attack Injector</b>", table_cell_style),
            Paragraph("<code>run_attack_demo.bat</code>", code_style),
            Paragraph("<code>.\\.venv\\Scripts\\python.exe simulate_attack.py</code>", code_style)
        ],
        [
            Paragraph("<b>🧪 Automated Unit Tests</b>", table_cell_style),
            Paragraph("<code>run_tests.bat</code>", code_style),
            Paragraph("<code>.\\.venv\\Scripts\\python.exe -m unittest tests/test_pipeline.py</code>", code_style)
        ],
        [
            Paragraph("<b>📁 Standalone PCAP Analyzer</b>", table_cell_style),
            Paragraph("—", table_cell_style),
            Paragraph("<code>.\\.venv\\Scripts\\python.exe analyze_pcap.py data/raw_pcaps/mixed_enterprise_traffic.pcap</code>", code_style)
        ]
    ]

    t_launch = Table(launch_data, colWidths=[120, 110, 274])
    t_launch.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0, 0), (-1, -1), 3.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3.5),
        ('LEFTPADDING', (0, 0), (-1, -1), 5),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(t_launch)

    # Build the PDF with dynamic running headers & page count
    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"Successfully generated PDF: {output_path}")

if __name__ == "__main__":
    out_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "DNS_Tunneling_Detection_Project_Documentation.pdf")
    create_project_pdf(out_file)
