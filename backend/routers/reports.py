"""
Reports Router
"""
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import StreamingResponse
from datetime import datetime, timezone
import io

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

from .dependencies import (
    get_current_user, get_db, check_permission, logger
)
from .ai_analysis import call_openai

router = APIRouter(prefix="/reports", tags=["Reports"])

def generate_threat_report_pdf(threats: list, alerts: list, stats: dict) -> io.BytesIO:
    """Generate PDF threat intelligence report"""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=72)
    
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name='TitleStyle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30,
        textColor=colors.HexColor('#3B82F6')
    ))
    styles.add(ParagraphStyle(
        name='SectionTitle',
        parent=styles['Heading2'],
        fontSize=14,
        spaceAfter=12,
        spaceBefore=20,
        textColor=colors.HexColor('#1E293B')
    ))
    styles.add(ParagraphStyle(
        name='CustomBody',
        parent=styles['Normal'],
        fontSize=10,
        spaceAfter=8
    ))
    
    elements = []
    
    # Title
    elements.append(Paragraph("THREAT INTELLIGENCE REPORT", styles['TitleStyle']))
    elements.append(Paragraph(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", styles['CustomBody']))
    elements.append(Spacer(1, 20))
    
    # Executive Summary
    elements.append(Paragraph("EXECUTIVE SUMMARY", styles['SectionTitle']))
    summary_data = [
        ['Metric', 'Value'],
        ['Total Threats', str(stats.get('total_threats', 0))],
        ['Active Threats', str(stats.get('active_threats', 0))],
        ['Contained Threats', str(stats.get('contained_threats', 0))],
        ['Resolved Threats', str(stats.get('resolved_threats', 0))],
        ['Critical Alerts', str(stats.get('critical_alerts', 0))],
        ['System Health', f"{stats.get('system_health', 100):.1f}%"]
    ]
    
    summary_table = Table(summary_data, colWidths=[200, 150])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3B82F6')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 11),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#F8FAFC')),
        ('TEXTCOLOR', (0, 1), (-1, -1), colors.HexColor('#1E293B')),
        ('FONTSIZE', (0, 1), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#E2E8F0')),
        ('ROWHEIGHT', (0, 0), (-1, -1), 25)
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 20))
    
    # Active Threats Section
    elements.append(Paragraph("ACTIVE THREATS", styles['SectionTitle']))
    active_threats = [t for t in threats if t.get('status') == 'active']
    
    if active_threats:
        threat_data = [['Name', 'Type', 'Severity', 'Source IP']]
        for threat in active_threats[:10]:
            threat_data.append([
                threat.get('name', 'Unknown')[:30],
                threat.get('type', 'Unknown'),
                threat.get('severity', 'Unknown').upper(),
                threat.get('source_ip', 'N/A')
            ])
        
        threat_table = Table(threat_data, colWidths=[150, 80, 80, 100])
        threat_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#EF4444')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#E2E8F0')),
            ('ROWHEIGHT', (0, 0), (-1, -1), 22)
        ]))
        elements.append(threat_table)
    else:
        elements.append(Paragraph("No active threats at this time.", styles['CustomBody']))
    
    elements.append(Spacer(1, 20))
    
    # Recent Alerts Section
    elements.append(Paragraph("RECENT ALERTS", styles['SectionTitle']))
    if alerts:
        alert_data = [['Title', 'Type', 'Severity', 'Status']]
        for alert in alerts[:10]:
            alert_data.append([
                alert.get('title', 'Unknown')[:35],
                alert.get('type', 'Unknown'),
                alert.get('severity', 'Unknown').upper(),
                alert.get('status', 'Unknown')
            ])
        
        alert_table = Table(alert_data, colWidths=[170, 80, 80, 80])
        alert_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#F59E0B')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#E2E8F0')),
            ('ROWHEIGHT', (0, 0), (-1, -1), 22)
        ]))
        elements.append(alert_table)
    else:
        elements.append(Paragraph("No recent alerts.", styles['CustomBody']))
    
    elements.append(Spacer(1, 30))
    
    # Footer
    elements.append(Paragraph("--- End of Report ---", styles['CustomBody']))
    elements.append(Paragraph("Generated by Anti-AI Defense System", styles['CustomBody']))
    
    doc.build(elements)
    buffer.seek(0)
    return buffer

@router.get("/threat-intelligence")
async def generate_threat_report(current_user: dict = Depends(check_permission("export_reports"))):
    """Generate PDF threat intelligence report"""
    db = get_db()
    
    # Gather data
    threats = await db.threats.find({}, {"_id": 0}).sort("created_at", -1).to_list(50)
    alerts = await db.alerts.find({}, {"_id": 0}).sort("created_at", -1).to_list(50)
    
    # Calculate stats
    total_threats = len(threats)
    active_threats = len([t for t in threats if t.get('status') == 'active'])
    contained_threats = len([t for t in threats if t.get('status') == 'contained'])
    resolved_threats = len([t for t in threats if t.get('status') == 'resolved'])
    critical_alerts = len([a for a in alerts if a.get('severity') == 'critical' and a.get('status') != 'resolved'])
    
    system_health = 100.0
    if total_threats > 0:
        system_health = ((contained_threats + resolved_threats) / total_threats) * 100
    
    stats = {
        'total_threats': total_threats,
        'active_threats': active_threats,
        'contained_threats': contained_threats,
        'resolved_threats': resolved_threats,
        'critical_alerts': critical_alerts,
        'system_health': system_health
    }
    
    # Generate PDF
    pdf_buffer = generate_threat_report_pdf(threats, alerts, stats)
    
    filename = f"threat_report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.pdf"
    
    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@router.post("/ai-summary")
async def generate_ai_summary_report(current_user: dict = Depends(check_permission("export_reports"))):
    """Generate AI-powered threat summary"""
    db = get_db()
    threats = await db.threats.find({}, {"_id": 0}).sort("created_at", -1).to_list(20)
    alerts = await db.alerts.find({}, {"_id": 0}).sort("created_at", -1).to_list(20)
    
    context = f"""
Threats Summary:
- Total: {len(threats)}
- Active: {len([t for t in threats if t.get('status') == 'active'])}
- Types: {', '.join(set(t.get('type', 'unknown') for t in threats))}

Alerts Summary:
- Total: {len(alerts)}
- Critical: {len([a for a in alerts if a.get('severity') == 'critical'])}

Recent Threat Names:
{chr(10).join(['- ' + t.get('name', 'Unknown') for t in threats[:5]])}
"""
    
    system_message = """You are a cybersecurity analyst. Provide a concise executive summary of the current threat landscape based on the data provided. Include:
1. Overall risk assessment (Critical/High/Medium/Low)
2. Key findings (3-5 bullet points)
3. Recommended immediate actions (2-3 points)
4. Trend analysis

Keep the summary professional and actionable."""

    try:
        summary = await call_openai(system_message, f"Analyze this security data and provide an executive summary:\n{context}")
        return {
            "summary": summary,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "data_points": {
                "threats_analyzed": len(threats),
                "alerts_analyzed": len(alerts)
            }
        }
    except Exception as e:
        logger.error(f"AI summary generation error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to generate summary: {str(e)}")
