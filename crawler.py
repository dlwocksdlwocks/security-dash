import datetime
import os
import re
import time
import urllib.parse
import zoneinfo
from bs4 import BeautifulSoup
from dotenv import load_dotenv
import feedparser
from openai import OpenAI
import requests

# 💡 SecurityNotice 및 모델 import
from database import (
    SecurityNews,
    SecurityNotice,
    SecurityVulnerability,
    SessionLocal,
    init_db,
)

load_dotenv()

# 💡 한국 표준시 (KST) 정의
KST = zoneinfo.ZoneInfo("Asia/Seoul")

api_key = os.getenv("OPENAI_API_KEY")
client = OpenAI(api_key=api_key)

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
        " (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
    ),
    "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7",
}


def extract_cve_code(text_sources):
    """제목과 본문 텍스트에서 CVE 번호를 찾아 추출합니다."""
    cve_pattern = r"CVE-\d{4}-\d{4,5}"
    for text in text_sources:
        if not text:
            continue
        match = re.search(cve_pattern, text, re.IGNORECASE)
        if match:
            return match.group(0).upper()
    return None


def classify_category_with_chatgpt(title, content):
    """뉴스 기사의 제목과 내용을 바탕으로 4개 카테고리 중 하나로 분류합니다."""
    prompt = f"""
    당신은 정보보안센터의 보안 뉴스 분류 전문가입니다.
    아래 보안 뉴스 기사의 제목과 내용을 분석하여, 가장 적합한 카테고리 하나만 딱 골라 답하세요.

    [카테고리 후보]
    1. 침해
    2. 해킹
    3. 개인정보
    4. 기타보안

    [응답 규칙]
    - 오직 카테고리명('침해', '해킹', '개인정보', '기타보안') 단어 하나만 반환할 것.

    [기사 제목]
    {title}

    [기사 본문 요약]
    {content[:500] if content else ''}
    """
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": "너는 보안 데이터 분류 전문가야. 지정된 4개 단어 중 하나만 반환해.",
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.0,
        )
        category = response.choices[0].message.content.strip()
        if category not in ["침해", "해킹", "개인정보", "기타보안"]:
            category = "기타보안"
        return category
    except Exception as e:
        print(f"❌ ChatGPT 카테고리 분류 실패: {e}")
        return "기타보안"


def summarize_with_chatgpt(title, content, source, author):
    """정보보안센터 브리핑 및 아카이브용 ChatGPT 요약 함수"""
    prompt = (
        f"출처: {source} ({author})\n"
        f"제목: {title}\n"
        f"본문 내용:\n{content}\n\n"
        f"너는 정보보안센터 전원(보안 기획 및 운영 팀원 전체)에게 공유할 일일 동향 브리핑을 작성해야 해.\n"
        f"센터원들이 출근길에 쉽고 명확하게 파악할 수 있도록 핵심 위협과 조치 사항을 중심으로 70글자 내로 짧게 요약해줘.\n"
        f"요약 끝에는 반드시 '출처: {source} ({author})'를 명시해줘."
    )

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "너는 정보보안센터의 CISO이자 종합 컨트롤타워야. 모든 보안"
                        " 직원이 직관적으로 이해할 수 있게 팩트 기반의 명확한 요약"
                        " 보고서를 작성하는 전문가야."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"❌ ChatGPT 요약 실패: {e}")
        return "요약 프로세스 일시적 제한"


def crawl_bohonara_notice(db):
    """KISA 보호나라 보안공지 게시판(B0000133)에서 최신 공지목록을 수집합니다."""
    print("\n📡 [KISA 보호나라] 보안 공지 수집 중...")
    list_url = "https://www.boho.or.kr/kr/bbs/list.do?menuNo=205020&bbsId=B0000133"

    try:
        res = requests.get(list_url, headers=HEADERS, timeout=10)
        res.encoding = "utf-8"
        soup = BeautifulSoup(res.text, "html.parser")

        post_items = soup.select("div.tbl_responsive table tbody tr")
        if not post_items:
            post_items = soup.select("table tbody tr")

        count = 0
        for tr in post_items:
            link_tag = tr.select_one("td.sbj.tal a") or tr.select_one("td a")
            if not link_tag:
                continue

            title = link_tag.get_text(strip=True)
            href = link_tag.get("href", "")

            parsed_url = urllib.parse.urlparse(href)
            params = urllib.parse.parse_qs(parsed_url.query)
            ntt_id = params.get("nttId", [None])[0]

            if not ntt_id and "nttId=" in href:
                ntt_id = href.split("nttId=")[1].split("&")[0]

            if not ntt_id:
                continue

            full_link = f"https://www.boho.or.kr/kr/bbs/view.do?menuNo=205020&bbsId=B0000133&nttId={ntt_id}"

            tds = tr.select("td")
            posted_date = ""
            for td in tds:
                text = td.get_text(strip=True)
                if re.match(r"^\d{4}-\d{2}-\d{2}$", text):
                    posted_date = text
                    break

            if not posted_date:
                posted_date = datetime.datetime.now(KST).strftime("%Y-%m-%d")

            exists = db.query(SecurityNotice).filter(SecurityNotice.link == full_link).first()
            if exists:
                continue

            try:
                notice = SecurityNotice(
                    title=title,
                    link=full_link,
                    posted_date=posted_date
                )
                db.add(notice)
                db.commit()
                count += 1
            except Exception as e:
                db.rollback()
                continue

        print(f"✅ [보호나라 공지] 신규 공지 {count}건 저장 완료.")

    except Exception as e:
        db.rollback()
        print(f"❌ [보호나라 공지] 크롤링 실패: {e}")


def crawl_bohonara_vulnerability(db):
    """KISA 보호나라 취약점 게시판에서 새 공지 1건을 수집하여 SecurityVulnerability 테이블에 저장합니다."""
    print("\n📡 [KISA 보호나라] 취약점 정보 수집 중 (nttId 기준)...")
    list_url = "https://www.boho.or.kr/kr/bbs/list.do?menuNo=205023&bbsId=B0000302"

    try:
        res = requests.get(list_url, headers=HEADERS, timeout=10)
        res.encoding = "utf-8"
        soup = BeautifulSoup(res.text, "html.parser")

        post_items = soup.select("div.tbl_responsive table tbody tr")
        if not post_items:
            post_items = soup.select("table tbody tr")

        if not post_items:
            print("❌ 보호나라 게시글 목록을 찾을 수 없습니다.")
            return

        for tr in post_items:
            link_tag = tr.select_one("td.sbj.tal a") or tr.select_one("td a")
            if not link_tag:
                continue

            title = link_tag.get_text(strip=True)
            href = link_tag.get("href", "")

            parsed_url = urllib.parse.urlparse(href)
            params = urllib.parse.parse_qs(parsed_url.query)
            ntt_id = params.get("nttId", [None])[0]

            if not ntt_id and "nttId=" in href:
                ntt_id = href.split("nttId=")[1].split("&")[0]

            if not ntt_id:
                continue

            full_link = f"https://www.boho.or.kr/kr/bbs/view.do?menuNo=205023&bbsId=B0000302&nttId={ntt_id}"

            exists = (
                db.query(SecurityVulnerability)
                .filter(
                    SecurityVulnerability.link.like(f"%nttId={ntt_id}%")
                )
                .first()
            )
            if exists:
                continue

            print(f"📰 새 취약점 공지 발견 (nttId: {ntt_id}): [KISA 보호나라] - {title}")
            content_text = ""
            try:
                detail_res = requests.get(full_link, headers=HEADERS, timeout=10)
                detail_res.encoding = "utf-8"
                detail_soup = BeautifulSoup(detail_res.text, "html.parser")

                view_content = detail_soup.select_one(".bbs_view_container")
                if view_content:
                    content_text = view_content.get_text(strip=True)[:2500]
                else:
                    content_text = detail_soup.get_text(strip=True)[:2500]
            except Exception:
                content_text = title

            cve_code = extract_cve_code([title, content_text])

            summary = summarize_with_chatgpt(
                title, content_text, "KISA 보호나라", "KISA 침해사고분석단"
            )

            now_kst = datetime.datetime.now(KST)

            article = SecurityVulnerability(
                source="KISA 보호나라",
                author="KISA 침해사고분석단",
                title=title,
                link=full_link,
                content=content_text,
                summary=summary,
                cve_code=cve_code,
                published_at=now_kst,
                created_at=now_kst,
            )
            db.add(article)
            db.commit()
            print(f"✅ 보호나라 최신 취약점 1건(nttId: {ntt_id}, CVE: {cve_code}) 저장 완료.")
            return

        print("⏭️ 보호나라에 새로 등록된 취약점 공지가 없습니다.")
    except Exception as e:
        db.rollback()
        print(f"❌ 보호나라 nttId 기반 크롤링 실패: {e}")

def crawl_rss_source(db, name, url, default_author):
    """RSS 피드 및 네이버 뉴스에서 최신 기사를 수집하고 AI로 카테고리를 분류하여 KST 시각으로 저장합니다."""
    print(f"\n📡 [{name}] 신규 위협 피드 수집 중...")
    try:
        session = requests.Session()
        response = session.get(url, headers=HEADERS, timeout=10)

        entries = []

        # 💡 1. 네이버 뉴스 웹페이지(HTML) 파싱 분기
        if "naver.com" in url:
            response.encoding = "utf-8"
            soup = BeautifulSoup(response.text, "html.parser")
            news_items = soup.select(".sa_item")

            for item in news_items:
                title_tag = item.select_one(".sa_text_title")
                if not title_tag:
                    continue
                
                # RSS Entry 객체처럼 사용할 더미 클래스 정의
                class NaverEntry:
                    pass
                
                e = NaverEntry()
                e.title = title_tag.get_text(strip=True)
                e.link = title_tag.get("href")
                
                # 언론사 이름 (예: 연합뉴스, 지디넷코리아 등)
                e.author = "네이버"
                
                # 요약문
                summary_tag = item.select_one(".sa_text_lede")
                e.description = summary_tag.get_text(strip=True) if summary_tag else ""
                
                entries.append(e)

        # 💡 2. 기존 RSS/XML 파싱 분기
        else:
            if "boannews" in url:
                response.encoding = "euc-kr"
            else:
                response.encoding = response.apparent_encoding

            feed = feedparser.parse(response.text)
            entries = feed.entries

            if not entries:
                soup = BeautifulSoup(response.text, "xml")
                items = soup.find_all("item")
                for item in items:
                    class Entry:
                        pass
                    e = Entry()
                    e.title = item.title.text if item.title else ""
                    e.link = item.link.text if item.link else ""
                    e.description = item.description.text if item.description else ""

                    date_tag = item.find("dc:date") or item.find("pubDate")
                    e.published = date_tag.text if date_tag else ""
                    entries.append(e)

        count = 0

        # 💡 3. 데이터 처리 및 DB 저장
        for entry in entries[:10]:
            if not entry.title:
                continue

            exists = (
                db.query(SecurityNews)
                .filter(SecurityNews.title == entry.title)
                .first()
            )
            if exists:
                continue

            author = default_author
            if hasattr(entry, "author") and entry.author:
                author = entry.author

            now_kst = datetime.datetime.now(KST)
            published_dt = now_kst

            pub_parsed = getattr(entry, "published_parsed", None) or getattr(entry, "updated_parsed", None)
            
            if pub_parsed:
                dt_utc = datetime.datetime(*pub_parsed[:6], tzinfo=datetime.timezone.utc)
                published_dt = dt_utc.astimezone(KST)
            elif hasattr(entry, "published") and entry.published:
                raw_date = entry.published.strip()
                try:
                    if len(raw_date) >= 10 and raw_date[:10].count("-") == 2:
                        date_part = raw_date[:10]
                        published_dt = datetime.datetime.strptime(date_part, "%Y-%m-%d").replace(tzinfo=KST)
                except Exception:
                    published_dt = now_kst

            print(f"📰 새 신규 위협 기사 발견: [{name}] - {entry.title} (발행일: {published_dt.strftime('%Y-%m-%d')})")
            
            content_text = ""
            try:
                res = session.get(entry.link, headers=HEADERS, timeout=10)
                
                # 💡 [수정 포인트] 개별 기사별 최적 인코딩 처리
                if "boannews" in entry.link:
                    res.encoding = "euc-kr"
                else:
                    res.encoding = res.apparent_encoding if res.encoding is None else res.encoding

                soup = BeautifulSoup(res.text, "html.parser")
                content_text = soup.get_text(strip=True)[:2500]
            except Exception:
                content_text = entry.description if hasattr(entry, "description") else ""

            try:
                # ChatGPT 기반 카테고리 분류 & 요약
                category = classify_category_with_chatgpt(entry.title, content_text)
                summary = summarize_with_chatgpt(entry.title, content_text, name, author)

                article = SecurityNews(
                    source=name, # 네이버일 경우 해당 기사의 언론사 이름 표시
                    author=author,
                    title=entry.title,
                    link=entry.link,
                    content=content_text,
                    summary=summary,
                    category=category,
                    created_at=now_kst,
                    published_at=published_dt,
                )
                db.add(article)
                db.commit()
                count += 1
            except Exception as item_err:
                db.rollback()
                print(f"⚠️ [{name}] 개별 기사 저장 중 에러 건너뜀: {item_err}")
                continue

        print(f"✅ [{name}] 새 기사 {count}건 저장 완료.")
    except Exception as e:
        db.rollback()
        print(f"❌ [{name}] 피드 파싱 실패: {e}")

def crawl_and_sync_all():
    print("🚀 카테고리별 보안 데이터 수집 및 센터 공지 요약 프로세스 가동 (ChatGPT)...")
    db = SessionLocal()
    try:
        crawl_bohonara_notice(db)
        crawl_bohonara_vulnerability(db)
        crawl_rss_source(
            db,
            "보안뉴스",
            "https://www.boannews.com/media/news_rss.xml",
            "보안뉴스 취재팀",
        )
        crawl_rss_source(
            db,
            "데일리시큐",
            "https://www.dailysecu.com/rss/clickTop.xml",
            "데일리시큐 취재기자",
        )
        crawl_rss_source(
            db, 
            "네이버뉴스", 
            "https://news.naver.com/breakingnews/section/105/732", 
            "네이버뉴스"
        )
    finally:
        db.close()
    print("\n🏁 모든 카테고리 데이터 수집 및 종합 요약 저장 완료!")


if __name__ == "__main__":
    init_db()
    crawl_and_sync_all()