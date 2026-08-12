import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

def send_daily_briefing_email(receiver_emails: list, news_data: dict, cve_list: list):
    """
    Gmail SMTP를 활용해 동료들에게 일일 이메일 단방향 브리핑 발송
    """
    smtp_server = "smtp.gmail.com"
    smtp_port = 465
    
    sender_email = os.getenv("GMAIL_USER")
    sender_password = os.getenv("GMAIL_PASS")

    if not sender_email or not sender_password:
        print("❌ [이메일] GMAIL_USER 또는 GMAIL_PASS 환경변수가 설정되지 않았습니다.")
        return

    categories = [
        ("1. 침해사고 동향", news_data.get("침해", [])),
        ("2. 해킹 및 악성코드", news_data.get("해킹", [])),
        ("3. 개인정보보호 이슈", news_data.get("개인정보", [])),
        ("4. 기타 보안 동향", news_data.get("기타", []))
    ]

    html_content = f"""
    <html>
    <body style="font-family: 'Malgun Gothic', '맑은 고딕', sans-serif; color: #333333; line-height: 1.6; background-color: #f4f6f9; padding: 20px 0; margin: 0;">
        <div style="max-width: 680px; margin: 0 auto; background-color: #ffffff; padding: 25px; border-radius: 8px; border: 1px solid #e2e8f0; box-shadow: 0 2px 5px rgba(0,0,0,0.05);">
            
            <div style="border-bottom: 3px solid #2b6cb0; padding-bottom: 15px; margin-bottom: 20px;">
                <h2 style="color: #1a365d; margin: 0 0 5px 0; font-size: 20px;">🛡️ Daily 보안 위협 인텔리전스 브리핑</h2>
                <p style="color: #718096; font-size: 13px; margin: 0;">CISO 및 정보보안 담당자를 위한 금일 주요 보안 이슈 요약</p>
            </div>

            <p style="font-size: 14px; color: #4a5568; margin-bottom: 20px;">
                안녕하세요, 오늘 수집 및 AI 2단계 필터링이 완료된 주요 보안 위협 요약 정보입니다.
            </p>
    """

    for cat_title, items in categories:
        html_content += f"""
        <div style="margin-top: 20px;">
            <h3 style="color: #2b6cb0; font-size: 15px; border-left: 4px solid #3182ce; padding-left: 8px; margin-bottom: 10px;">{cat_title}</h3>
        """
        top_items = items[:2] if items else []
        if top_items:
            for item in top_items:
                html_content += f"""
                <div style="background-color: #f8fafc; border: 1px solid #e2e8f0; padding: 12px 15px; border-radius: 6px; margin-bottom: 8px;">
                    <div style="font-weight: bold; font-size: 13px; color: #2d3748; margin-bottom: 4px;">• {item.get('title')}</div>
                    <div style="font-size: 12px; color: #4a5568; margin-bottom: 6px; background-color: #ffffff; padding: 8px; border-radius: 4px; border: 1px solid #edf2f7;">
                        <b>[CISO 요약]</b> {item.get('summary', '요약 정보가 없습니다.')}
                    </div>
                    <a href="{item.get('link', '#')}" target="_blank" style="font-size: 11px; color: #3182ce; text-decoration: none;">🔗 원문 기사 확인</a>
                </div>
                """
            if len(items) > 2:
                html_content += f"""
                <div style="font-size: 11px; color: #718096; text-align: right; margin-top: 2px;">
                    외 {len(items) - 2}건의 관련 이슈가 더 있습니다.
                </div>
                """
        else:
            html_content += """<p style="font-size: 12px; color: #a0aec0; margin-left: 10px; margin-top: 5px;">• 금일 관련 주요 이슈가 없습니다.</p>"""
        html_content += "</div>"

    html_content += """
        <div style="margin-top: 25px; border-top: 2px dashed #e2e8f0; padding-top: 15px;">
            <h3 style="color: #c53030; font-size: 15px; border-left: 4px solid #e53e3e; padding-left: 8px; margin-bottom: 10px;">⚠️ 금일 주요 CVE 취약점 (Top 3)</h3>
    """
    
    top_cves = cve_list[:3] if cve_list else []
    if top_cves:
        for cve in top_cves:
            html_content += f"""
            <div style="background-color: #fff5f5; border: 1px solid #fed7d7; padding: 8px 12px; border-radius: 6px; margin-bottom: 6px;">
                <span style="font-weight: bold; color: #c53030; font-size: 12px;">[{cve.get('code', 'CVE ID')}]</span>
                <span style="font-size: 12px; color: #2d3748; margin-left: 6px;">{cve.get('title')}</span>
            </div>
            """
    else:
        html_content += """<p style="font-size: 12px; color: #a0aec0; margin-left: 10px; margin-top: 5px;">• 금일 수집된 신규 CVE 취약점 코드가 없습니다.</p>"""

    html_content += """
        </div>
        <div style="text-align: center; margin: 30px 0 15px 0;">
            <a href="https://security-dash.onrender.com" target="_blank" 
               style="background-color: #3182ce; color: #ffffff; padding: 11px 22px; font-size: 13px; font-weight: bold; text-decoration: none; border-radius: 6px; display: inline-block;">
                🌐 웹 대시보드에서 전체 위협 정보 확인하기
            </a>
        </div>
        <div style="text-align: center; margin-top: 25px; border-top: 1px solid #edf2f7; padding-top: 15px; font-size: 12px; color: #a0aec0;">
            <p style="margin: 0;">본 메일은 보안 위협 인텔리전스 시스템(security-dash)에서 자동 발송되는 <b>[발신 전용]</b> 메시지입니다.</p>
        </div>
    </div>
    </body>
    </html>
    """

    try:
        with smtplib.SMTP_SSL(smtp_server, smtp_port, timeout=15) as server:
            server.login(sender_email, sender_password)
            
            for receiver in receiver_emails:
                msg = MIMEMultipart('alternative')
                msg['Subject'] = "[보안 브리핑] 금일 주요 보안 위협 및 CVE 취약점 요약"
                msg['From'] = f"KOMSCO 보안인텔리전스 <{sender_email}>"
                msg['To'] = receiver
                msg.attach(MIMEText(html_content, 'html'))
                
                server.sendmail(sender_email, receiver, msg.as_string())
                print(f"✅ [이메일 완료] {receiver} 님에게 발송 성공")
    except Exception as e:
        print(f"❌ [이메일 오류] Gmail 발송 실패: {e}")