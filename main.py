import asyncio
import datetime
import json
import os
import random
import zoneinfo
from apscheduler.schedulers.background import BackgroundScheduler
from clear_db import reset_SecurityVulnerability
from crawler import crawl_and_sync_all
from database import (
    SecurityNews,
    SecurityNotice,
    SecurityVulnerability,
    SessionLocal,
    init_db,
)
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from openai import OpenAI
from sqlalchemy import func
from sqlalchemy.orm import Session
from email_service import send_daily_briefing_email

load_dotenv()

app = FastAPI(title="정보보안센터 위협 인텔리전스 대시보드")

init_db()

# 수신인 메일 목록 (테스트용 및 부서원 주소)
RECEIVER_EMAILS = [
    "jaechanjj@komsco.com"
]

def trigger_daily_email():
    """
    DB에서 오늘 자 뉴스 및 CVE 데이터를 조회하여 이메일 브리핑 발송
    """
    db = SessionLocal()
    try:
        KST = zoneinfo.ZoneInfo("Asia/Seoul")
        today = datetime.datetime.now(KST).date()

        # 1. DB에서 오늘 자 뉴스 조회 및 카테고리별 분류
        today_news_items = (
            db.query(SecurityNews)
            .filter(func.date(SecurityNews.created_at) == today)
            .order_by(SecurityNews.id.desc())
            .all()
        )

        categorized_news = {
            "침해": [],
            "해킹": [],
            "개인정보": [],
            "기타": []
        }

        for news in today_news_items:
            cat = news.category if news.category in categorized_news else "기타"
            categorized_news[cat].append({
                "title": news.title,
                "summary": news.summary if hasattr(news, "summary") and news.summary else "",
                "link": news.link
            })

        # 2. DB에서 최근 수집된 CVE 취약점 항목 조회
        latest_cve_record = (
            db.query(SecurityVulnerability)
            .order_by(SecurityVulnerability.created_at.desc())
            .first()
        )

        cve_data = []
        if latest_cve_record and latest_cve_record.created_at:
            latest_cve_date = latest_cve_record.created_at.date()
            cve_items = (
                db.query(SecurityVulnerability)
                .filter(func.date(SecurityVulnerability.created_at) == latest_cve_date)
                .order_by(SecurityVulnerability.created_at.desc())
                .all()
            )
            cve_data = [
                {
                    "code": cve.cve_code if cve.cve_code else "CVE ID",
                    "title": cve.title,
                    "summary": cve.summary if cve.summary else ""
                }
                for cve in cve_items
            ]

        # 3. 단방향 이메일 발송 함수 호출
        send_daily_briefing_email(
            receiver_emails=RECEIVER_EMAILS,
            news_data=categorized_news,
            cve_list=cve_data
        )
        print("🎉 [이메일 완료] 브리핑 이메일 발송 완료")
    except Exception as e:
        print(f"❌ [이메일 오류] 발송 실패: {e}")
    finally:
        db.close()


# 스케줄러 설정
scheduler = BackgroundScheduler()
# 12시간 주기 크롤링 실행
scheduler.add_job(crawl_and_sync_all, "interval", hours=12)
# 매일 14:00 자동 발송 스케줄도 유지
scheduler.add_job(trigger_daily_email, "cron", hour=14, minute=0, timezone="Asia/Seoul")
scheduler.start()


@app.on_event("startup")
async def startup_event():
    # 1. 서버 시작 직후 신규 크롤링 1회 수집
    await asyncio.to_thread(crawl_and_sync_all)
    # 2. 크롤링 완료 후 즉시 메일 테스트 발송 실행 🚀
    await asyncio.to_thread(trigger_daily_email)


# 프론트엔드 연동 CORS 설정
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def generate_ciso_view(category: str, news_list: list) -> str:
    """카테고리 선택 시 최신 뉴스 본문 기반 [서론-본론-결론] CISO 뷰포인트 생성"""
    if not category:
        return (
            "👋 안녕하세요! 정보보안센터 일일 보안 알람 대시보드입니다.\n"
            "좌측 '금일 신규 보안 이슈'에서 카테고리(침해, 해킹, 개인정보, 기타)를 선택하시면 "
            "해당 분야의 AI 맞춤형 보안 뷰포인트를 확인하실 수 있습니다."
        )

    if not news_list:
        return f"현재 [{category}] 카테고리에 오늘 수집된 신규 동향 뉴스가 없습니다."

    news_context = ""
    for idx, news in enumerate(news_list[:5]):
        title = news.title
        summary = (
            news.summary
            if hasattr(news, "summary") and news.summary
            else getattr(news, "content", "")[:150]
        )
        news_context += f"[{idx+1}] 제목: {title}\n    내용: {summary}\n\n"

    prompt = f"""
    너는 정보보안센터의 CISO이자 최상위 자산 분석가야.
    아래는 오늘 수집된 [{category}] 카테고리 관련 최신 뉴스 및 위협 동향 본문 데이터야.

    {news_context}

    [요구사항]
    위 뉴스 내용 전체를 종합 분석하여, 우리 보안팀과 센터장님께 보고할 [서론-본론-결론] 형태의 보안 뷰포인트를 작성해줘.

    [작성 규칙]
    1. 서론: 금일 [{category}] 관련 주요 위협 흐름 및 배경 요약 (1문장)
    2. 본문: 기술적 핵심 위협 요소 및 대상(DB, OS, Web, 단말, 네트워크 중 선택) 지정 (1문장)
    3. 결론: 오늘 우리 보안팀이 즉시 수행해야 할 강력하고 구체적인 대응 지침 (1문장)
    4. 특정 회사 이름은 언급하지 말고, '서론:', '본론:', '결론:' 같은 머리말 표기 없이 자연스러운 3문장(한 단락)으로 연결해서 작성해줘.
    """

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "너는 정보보안센터의 CISO야. 수집된 보안 뉴스의 본문 문맥을 종합 분석하여 "
                        "서론(동향)-본론(기술위협)-결론(대응지침) 구조의 명확한 3문장 종합 보고서를 작성해."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        print(f"❌ CISO 뷰포인트 생성 실패: {e}")
        return f"[{category}] 관련 주요 시스템 접근제어 정책 및 취약점 패치 현황 점검 요망"


@app.get("/api/dashboard")
def get_dashboard_data(
    category: str = Query(
        None, description="선택된 카테고리 (침해, 해킹, 개인정보, 기타보안)"
    ),
    db: Session = Depends(get_db),
):

    KST = zoneinfo.ZoneInfo("Asia/Seoul")
    today = datetime.datetime.now(KST).date()

    categories = ["침해", "해킹", "개인정보", "기타보안"]
    news_by_category = {}

    for cat in categories:
        items = (
            db.query(SecurityNews)
            .filter(
                SecurityNews.category == cat,
                func.date(SecurityNews.created_at) == today,
            )
            .order_by(SecurityNews.id.desc())
            .limit(10)
            .all()
        )

        news_by_category[cat] = [
            {
                "id": news.id,
                "title": news.title,
                "source": getattr(news, "source", "보안뉴스"),
                "link": news.link,
                "summary": news.summary if hasattr(news, "summary") else "",
                "created_at": (
                    news.created_at.strftime("%Y-%m-%d")
                    if hasattr(news, "created_at") and news.created_at
                    else ""
                ),
            }
            for news in items
        ]

    selected_news = (
        db.query(SecurityNews)
        .filter(
            SecurityNews.category == category,
            func.date(SecurityNews.created_at) == today,
        )
        .order_by(SecurityNews.id.desc())
        .limit(5)
        .all()
        if category
        else []
    )
    ciso_view = generate_ciso_view(category, selected_news)

    latest_record = (
        db.query(SecurityVulnerability)
        .order_by(SecurityVulnerability.created_at.desc())
        .first()
    )

    daily_vulnerabilities = []
    latest_cve_date_str = ""

    if latest_record and latest_record.created_at:
        latest_date = latest_record.created_at.date()
        latest_cve_date_str = latest_date.strftime("%Y-%m-%d")

        items = (
            db.query(SecurityVulnerability)
            .filter(func.date(SecurityVulnerability.created_at) == latest_date)
            .order_by(SecurityVulnerability.created_at.desc())
            .all()
        )

        daily_vulnerabilities = [
            {
                "id": v.id,
                "cve_code": v.cve_code if v.cve_code else None,
                "title": v.title,
                "summary": v.summary if v.summary else "",
                "link": v.link if v.link else "#",
                "created_at": (
                    v.created_at.strftime("%Y-%m-%d") if v.created_at else ""
                ),
            }
            for v in items
        ]

    latest_notice = (
        db.query(SecurityNotice)
        .order_by(SecurityNotice.posted_date.desc())
        .first()
    )
    latest_notices = []
    notice_date_str = ""

    if latest_notice:
        notice_date_str = latest_notice.posted_date
        items = (
            db.query(SecurityNotice)
            .filter(SecurityNotice.posted_date == notice_date_str)
            .order_by(SecurityNotice.id.desc())
            .limit(5)
            .all()
        )
        latest_notices = [
            {
                "id": n.id,
                "title": n.title,
                "link": n.link,
                "posted_date": n.posted_date,
            }
            for n in items
        ]

    return {
        "selected_category": category,
        "ciso_view": ciso_view,
        "news_by_category": news_by_category,
        "latest_notices": {
            "target_date": notice_date_str,
            "list": latest_notices,
        },
        "latest_cves": {
            "target_date": latest_cve_date_str,
            "list": daily_vulnerabilities,
        },
    }

# 루트 및 정적 파일 매핑
app.mount("/", StaticFiles(directory=".", html=True), name="static")