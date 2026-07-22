import asyncio
import datetime
import zoneinfo
import json
import os
from apscheduler.schedulers.background import BackgroundScheduler
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from openai import OpenAI
from sqlalchemy import func
from sqlalchemy.orm import Session
import random
from crawler import crawl_and_sync_all
from database import SecurityNews,SecurityNotice ,SecurityVulnerability, SessionLocal, init_db

load_dotenv()

app = FastAPI(title="정보보안센터 위협 인텔리전스 대시보드")

init_db()

# 스케줄러 설정 (12시간 주기로 반복)
scheduler = BackgroundScheduler()
scheduler.add_job(crawl_and_sync_all, "interval", hours=12)
scheduler.start()


@app.on_event("startup")
async def startup_event():
    # 서버 시작 직후 신규 크롤링 1회 수집
    asyncio.create_task(asyncio.to_thread(crawl_and_sync_all))


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

    # 💡 뉴스 제목뿐만 아니라 주요 본문 요약(summary)까지 학습 문맥에 포함
    news_context = ""
    for idx, news in enumerate(news_list[:5]):
        title = news.title
        # DB의 summary나 content 활용
        summary = news.summary if hasattr(news, 'summary') and news.summary else getattr(news, 'content', '')[:150]
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
            model="gpt-4o-mini",  # 💡 기존 모델(gpt-4o-mini) 그대로 유지
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
    category: str = Query(None, description="선택된 카테고리 (침해, 해킹, 개인정보, 기타보안)"),
    db: Session = Depends(get_db),
):
    
    # 한국 표준시 기준 오늘 날짜 구하기
    KST = zoneinfo.ZoneInfo("Asia/Seoul")
    today = datetime.datetime.now(KST).date() # 👈 서버 타임존과 무관하게 무조건 한국 오늘 날짜!
    
    categories = ["침해", "해킹", "개인정보", "기타보안"]
    news_by_category = {}

    # 1. 4개 카테고리별 오늘 자 신규 뉴스만 엄격 수집
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

    # 2. 선택된 카테고리의 '오늘 자' 기사 기반 동적 CISO 뷰포인트 생성
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

    # 3. 무작위 CVE 1건 추출
    vulnerabilities = db.query(SecurityVulnerability).all()
    random_vulnerability = None

    if vulnerabilities:
        # 오늘 날짜(예: 20260721)를 시드(Seed)값으로 설정하여 하루 동안 고정
        date_seed = int(today.strftime("%Y%m%d"))
        rnd = random.Random(date_seed)
        random_vulnerability = rnd.choice(vulnerabilities)

    # 가장 최근에 등록된 공지사항 날짜 찾기
    latest_notice = db.query(SecurityNotice).order_by(SecurityNotice.posted_date.desc()).first()
    latest_notices = []
    notice_date_str = ""

    if latest_notice:
        notice_date_str = latest_notice.posted_date
        # 해당 최신 날짜에 등록된 모든 공지글 가져오기 (최대 5건)
        items = (
            db.query(SecurityNotice)
            .filter(SecurityNotice.posted_date == notice_date_str)
            .order_by(SecurityNotice.id.desc())
            .limit(5)
            .all()
        )
        latest_notices = [
            {"id": n.id, "title": n.title, "link": n.link, "posted_date": n.posted_date}
            for n in items
        ]

    return {
        "selected_category": category,
        "ciso_view": ciso_view,
        "news_by_category": news_by_category,
        "latest_notices": {
            "target_date": notice_date_str,
            "list": latest_notices
        },
        "random_cve": (
            {
                "id": random_vulnerability.id,
                "cve_code": (
                    random_vulnerability.cve_code
                    if random_vulnerability
                    else None
                ),
                "title": (
                    random_vulnerability.title
                    if random_vulnerability
                    else "저장된 취약점 없음"
                ),
                "summary": (
                    random_vulnerability.summary
                    if random_vulnerability
                    else ""
                ),
                "link": (
                    random_vulnerability.link
                    if random_vulnerability
                    else "#"
                ),
            }
            if random_vulnerability
            else None
        ),
    }


# 루트 및 정적 파일 매핑
app.mount("/", StaticFiles(directory=".", html=True), name="static")