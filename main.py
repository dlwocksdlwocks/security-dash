from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func
from sqlalchemy.orm import Session
from database import SessionLocal, init_db,SecurityVulnerability, SecurityNews
from openai import OpenAI
import json
import os
from dotenv import load_dotenv
from fastapi.staticfiles import StaticFiles
import asyncio
# 💡 이 부분이 반드시 들어가야 합니다!
from crawler import fetch_security_news

# 스케쥴러
import asyncio
from apscheduler.schedulers.background import BackgroundScheduler

load_dotenv()

app = FastAPI(title="정보보안센터 위협 인텔리전스 대시보드")

init_db()

# 스케줄러 설정
scheduler = BackgroundScheduler()
# 12시간마다 뉴스 수집 함수 실행
scheduler.add_job(fetch_security_news, "interval", hours=12)
# 스케줄러 시작 (12시간 주기로 반복)
scheduler.start()

from backfill_categories import run_backfill

@app.on_event("startup")
async def startup_event():
    # 백그라운드로 1회 실행
    await asyncio.to_thread(run_backfill)
    
    # 서버 시작 직후 신규 크롤링 1회 수집
    asyncio.create_task(asyncio.to_thread(fetch_security_news))

    

# 프론트엔드 연동을 위한 CORS 설정
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

def analyze_news_with_gpt(recent_news):
    """최근 뉴스 5개를 학습하여 CISO 보안관점 한마디와 유출 기사를 한 번에 분석합니다."""
    if not recent_news:
        return {
            "ciso_view": "현재 수집된 신규 동향 뉴스가 없습니다. 인프라 기본 보안 정책을 유지하십시오.",
            "leak_title": "유출 관련 동향 없음",
            "leak_summary": "최근 5건 내에 개인정보 및 데이터 유출 관련 뉴스가 존재하지 않습니다."
        }
        
    news_context = ""
    for idx, news in enumerate(recent_news):
        news_context += f"[{idx}] 제목: {news.title}\n본문: {news.content[:500]}\n\n"

    prompt = (
        f"너는 정보보안센터의 CISO이자 최상위 자산 분석가야. 아래 최근 보안 뉴스 5건을 분석해줘.\n\n"
        f"{news_context}"
        f"요구사항:\n"
        f"1. 오늘 우리 보안팀이 가장 집중해야 할 핵심 보안적 조치 사항을 40자 내외의 아주 기술적이고 명령어 형태인 '한마디'로 작성해줘. 다만, 특정 회사이름이 들어가면 안되고 해당 사건을 취합해 봤을 때 기술적으로 어떤 관점이 필요한지를 적어줘 특히 db,os,단말등 중에 하나를 짚어서 이야기 해줘야해 (예: 'DB/Web 서버 최신 보안 패치 적용 및 취약 포트 차단 조치 요망')\n"
        f"2. 제공된 5건의 뉴스 중 '개인정보 유출', '데이터 침해(Data Breach)'등 '유출 사고'와 가장 관련이 깊은 기사 1개를 선정해서 그 기사의 제목และ 핵심 요약(70자 내외)을 적어줘. 만약 관련 기사가 전혀 없다면 가장 위험도가 높은 기사를 선정해줘.\n\n"
        f"반드시 아래 JSON 형식으로만 답변해줘. 다른 설명은 금지해.\n"
        f"{{\n"
        f"  \"ciso_view\": \"CISO 관점 한마디 내용\",\n"
        f"  \"leak_title\": \"선정된 유출 기사 제목\",\n"
        f"  \"leak_summary\": \"유출 기사 요약 내용\"\n"
        f"}}"
    )

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "너는 보안 데이터 가공 전문가이며 정해진 JSON 포맷으로만 출력하는 봇이야."},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"},
            temperature=0.2
        )
        return json.loads(response.choices[0].message.content)
    except Exception as e:
        print(f"❌ GPT 분석 실패: {e}")
        return {
            "ciso_view": "인프라 자산 취약점 모니터링 및 방화벽 접근제어 정책 점검 요망",
            "leak_title": "데이터 분석 프로세스 오류",
            "leak_summary": "실시간 뉴스 분석 중 일시적인 API 지연이 발생했습니다."
        }

@app.get("/api/dashboard")
def get_dashboard_data(db: Session = Depends(get_db)):
    # 1 & 4. 최근 뉴스 5개 수집 및 AI 종합 분석
    recent_news = db.query(SecurityNews).order_by(SecurityNews.id.desc()).limit(5).all()
    gpt_analysis = analyze_news_with_gpt(recent_news)
    
    # 2. 오른쪽 첫번째: 신규 CVE (보호나라 최신 5건)
    # new_vulnerabilities = db.query(SecurityVulnerability).order_by(SecurityVulnerability.id.desc()).limit(5).all()
    
    # 3. 오른쪽 두번째: 무작위 과거 CVE 1건 추출
    random_vulnerability = db.query(SecurityVulnerability).order_by(func.random()).first()
    
    return {
        "ciso_view": gpt_analysis.get("ciso_view"),
        "latest_news": [
            {
                "id": news.id,
                "title": news.title,
                "source": getattr(news, "source", "보안뉴스"),
                "link": news.link,
                "created_at": (
                    news.created_at.strftime("%Y-%m-%d")
                    if hasattr(news, "created_at") and news.created_at
                    else ""
                ),
            }
            for news in recent_news
        ],
        "random_cve": {
            "id": random_vulnerability.id,
            "cve_code": random_vulnerability.cve_code if random_vulnerability else None,
            "title": random_vulnerability.title if random_vulnerability else "저장된 취약점 없음",
            "summary": random_vulnerability.summary if random_vulnerability else "",
            "link": random_vulnerability.link if random_vulnerability else "#"
        } if random_vulnerability else None,
        "leak_section": {
            "title": gpt_analysis.get("leak_title"),
            "summary": gpt_analysis.get("leak_summary")
        }
    }

# 현재 폴더(".")에 있는 index.html 등의 파일을 루트("/") 경로로 접근할 수 있게 매핑
app.mount("/", StaticFiles(directory=".", html=True), name="static")