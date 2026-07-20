import feedparser
import requests
from bs4 import BeautifulSoup
from openai import OpenAI
from database import SessionLocal, init_db, SecurityVulnerability, SecurityNews
import datetime
import time
import urllib.parse
import re 
import os
from dotenv import load_dotenv

load_dotenv()

api_key = os.getenv("OPENAI_API_KEY")
client = OpenAI(api_key=api_key)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7"
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
                {"role": "system", "content": "너는 정보보안센터의 CISO이자 종합 컨트롤타워야. 모든 보안 직원이 직관적으로 이해할 수 있게 팩트 기반의 명확한 요약 보고서를 작성하는 전문가야."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"❌ ChatGPT 요약 실패: {e}")
        return "요약 프로세스 일시적 제한"

def crawl_bohonara_vulnerability(db):
    """KISA 보호나라 취약점 게시판에서 새 공지 1건을 수집하여 SecurityVulnerability 테이블에 저장합니다."""
    print("\n📡 [KISA 보호나라] 취약점 정보 수집 중 (nttId 기준)...")
    list_url = "https://www.boho.or.kr/kr/bbs/list.do?menuNo=205023&bbsId=B0000302"
    
    try:
        res = requests.get(list_url, headers=HEADERS, timeout=10)
        res.encoding = 'utf-8'
        soup = BeautifulSoup(res.text, 'html.parser')
        
        post_items = soup.select("div.tbl_responsive table tbody tr")
        if not post_items:
            post_items = soup.select("table tbody tr")
            
        if not post_items:
            print("❌ 보호나라 게시글 목록을 찾을 수 없습니다.")
            return

        for tr in post_items:
            link_tag = tr.select_one("td.sbj.tal a")
            if not link_tag:
                link_tag = tr.select_one("td a")
                
            if not link_tag:
                continue
                
            title = link_tag.get_text(strip=True)
            href = link_tag.get('href', '')
            
            parsed_url = urllib.parse.urlparse(href)
            params = urllib.parse.parse_qs(parsed_url.query)
            ntt_id = params.get('nttId', [None])[0]
            
            if not ntt_id and 'nttId=' in href:
                ntt_id = href.split('nttId=')[1].split('&')[0]
            
            if not ntt_id:
                continue

            full_link = f"https://www.boho.or.kr/kr/bbs/view.do?menuNo=205023&bbsId=B0000302&nttId={ntt_id}"
            
            exists = db.query(SecurityVulnerability).filter(SecurityVulnerability.link.like(f"%nttId={ntt_id}%")).first()
            if exists:
                continue  
                
            print(f"📰 새 취약점 공지 발견 (nttId: {ntt_id}): [KISA 보호나라] - {title}")
            content_text = ""
            try:
                detail_res = requests.get(full_link, headers=HEADERS, timeout=10)
                detail_res.encoding = 'utf-8'
                detail_soup = BeautifulSoup(detail_res.text, 'html.parser')
                
                view_content = detail_soup.select_one(".bbs_view_container")
                if view_content:
                    content_text = view_content.get_text(strip=True)[:2500]
                else:
                    content_text = detail_soup.get_text(strip=True)[:2500]
            except Exception:
                content_text = title
                
            cve_code = extract_cve_code([title, content_text])
                
            summary = summarize_with_chatgpt(title, content_text, "KISA 보호나라", "KISA 침해사고분석단")
            
            article = SecurityVulnerability(
                source="KISA 보호나라",
                author="KISA 침해사고분석단",
                title=title,
                link=full_link,
                content=content_text,
                summary=summary,
                cve_code=cve_code,
                published_at=datetime.datetime.now(datetime.timezone.utc)
            )
            db.add(article)
            db.commit()
            print(f"✅ 보호나라 최신 취약점 1건(nttId: {ntt_id}, CVE: {cve_code}) 저장 완료.")
            return  
            
        print("⏭️ 보호나라에 새로 등록된 취약점 공지가 없습니다.")
    except Exception as e:
        print(f"❌ 보호나라 nttId 기반 크롤링 실패: {e}")

def crawl_rss_source(db, name, url, default_author):
    """보안뉴스 및 데일리시큐 RSS 피드에서 각각 최신 5건을 수집하여 SecurityNews 테이블에 저장합니다."""
    print(f"\n📡 [{name}] 신규 위협 피드 수집 중...")
    try:
        session = requests.Session()
        response = session.get(url, headers=HEADERS, timeout=10)
        
        if "boannews" in url:
            response.encoding = "euc-kr"
        else:
            response.encoding = response.apparent_encoding

        feed = feedparser.parse(response.text)
        
        if not feed.entries:
            soup = BeautifulSoup(response.text, 'xml')
            items = soup.find_all('item')
            feed.entries = []
            for item in items:
                class Entry: pass
                e = Entry()
                e.title = item.title.text if item.title else ""
                e.link = item.link.text if item.link else ""
                e.description = item.description.text if item.description else ""
                feed.entries.append(e)

        count = 0
        for entry in feed.entries[:5]:
            if not entry.title:
                continue
                
            exists = db.query(SecurityNews).filter(SecurityNews.title == entry.title).first()
            if exists:
                continue
                
            author = default_author
            if hasattr(entry, 'author') and entry.author:
                author = entry.author
                
            print(f"📰 새 신규 위협 기사 발견: [{name}] - {entry.title}")
            
            content_text = ""
            try:
                res = session.get(entry.link, headers=HEADERS, timeout=10)
                res.encoding = response.encoding
                soup = BeautifulSoup(res.text, 'html.parser')
                content_text = soup.get_text(strip=True)[:2500]
            except Exception:
                content_text = entry.description if hasattr(entry, 'description') else ""
                
            summary = summarize_with_chatgpt(entry.title, content_text, name, author)
            
            article = SecurityNews(
                source=name,
                author=author,
                title=entry.title,
                link=entry.link,
                content=content_text,
                summary=summary,
                published_at=datetime.datetime.now(datetime.timezone.utc)
            )
            db.add(article)
            count += 1
            
        db.commit()
        print(f"✅ [{name}] 새 기사 {count}건 저장 완료.")
    except Exception as e:
        print(f"❌ [{name}] 피드 파싱 실패: {e}")


def fetch_all_bohonara():
    """KISA 보호나라 과거 취약점 공지 전체 페이지를 순회하며 아카이브를 구축합니다."""
    print("🚀 [KISA 보호나라] 과거 취약점 공지 전체 수집 프로세스 가동 (분리형 DB + CVE 매핑)...")
    
    page = 1
    total_saved = 0
    
    while True:
        print(f"\n📖 보호나라 {page}페이지 탐색 중...")
        list_url = f"https://www.boho.or.kr/kr/bbs/list.do?menuNo=205023&bbsId=B0000302&pageIndex={page}"
        
        try:
            res = requests.get(list_url, headers=HEADERS, timeout=10)
            res.encoding = 'utf-8'
            soup = BeautifulSoup(res.text, 'html.parser')
            
            post_items = soup.select("div.tbl_responsive table tbody tr")
            if not post_items:
                print(f"🏁 {page}페이지에 게시글이 없습니다. 수집을 종료합니다.")
                break

            # 페이지마다 독립적인 DB 세션 사용
            db = SessionLocal()
            page_saved_count = 0
            
            try:
                for tr in post_items:
                    link_tag = tr.select_one("td.sbj.tal a")
                    if not link_tag:
                        continue
                        
                    title = link_tag.get_text(strip=True)
                    href = link_tag.get('href', '')
                    
                    parsed_url = urllib.parse.urlparse(href)
                    params = urllib.parse.parse_qs(parsed_url.query)
                    ntt_id = params.get('nttId', [None])[0]
                    
                    if not ntt_id and 'nttId=' in href:
                        ntt_id = href.split('nttId=')[1].split('&')[0]
                    
                    if not ntt_id:
                        continue

                    full_link = f"https://www.boho.or.kr/kr/bbs/view.do?menuNo=205023&bbsId=B0000302&nttId={ntt_id}"
                    
                    # 이미 수집된 건인지 검사
                    exists = db.query(SecurityVulnerability).filter(
                        SecurityVulnerability.link.like(f"%nttId={ntt_id}%")
                    ).first()
                    
                    if exists:
                        print(f"⏭️ nttId {ntt_id}는 이미 DB에 존재하므로 패스합니다.")
                        continue 

                    content_text = ""
                    try:
                        detail_res = requests.get(full_link, headers=HEADERS, timeout=10)
                        detail_res.encoding = 'utf-8'
                        detail_soup = BeautifulSoup(detail_res.text, 'html.parser')
                        
                        view_content = detail_soup.select_one(".bbs_view_container")
                        content_text = view_content.get_text(strip=True)[:2500] if view_content else title
                    except Exception:
                        content_text = title
                    
                    cve_code = extract_cve_code([title, content_text])
                    print(f"📰 새 취약점 발견 (nttId: {ntt_id}) [CVE: {cve_code}]: {title}")
                    
                    summary = summarize_with_chatgpt(title, content_text, "KISA 보호나라", "KISA 침해사고분석단")
                    
                    article = SecurityVulnerability(
                        source="KISA 보호나라",
                        author="KISA 침해사고분석단",
                        title=title,
                        link=full_link,
                        content=content_text,
                        summary=summary,
                        cve_code=cve_code, 
                        published_at=datetime.datetime.now(datetime.timezone.utc)
                    )
                    db.add(article)
                    page_saved_count += 1
                    total_saved += 1
                    
                    time.sleep(1) # API/서버 매너 요청 간격 (1초)
                    
                db.commit()
                print(f"✅ {page}페이지 완료 (이번 페이지에서 {page_saved_count}건 저장됨)")
                page += 1
                
            except Exception as inner_e:
                db.rollback()
                print(f"❌ {page}페이지 DB 저장 중 에러 발생: {inner_e}")
                break
            finally:
                db.close() # 페이지 작업이 끝날 때마다 안전하게 세션 닫기
                
        except Exception as e:
            print(f"❌ {page}페이지 크롤링 도중 네트워크/파싱 에러 발생: {e}")
            break
            
    print(f"\n🏁 수집 전면 완료! 총 {total_saved}건의 데이터가 security_vulnerabilities 테이블에 적재되었습니다.")

def crawl_and_sync_all():
    print("🚀 카테고리별 보안 데이터 수집 및 센터 공지 요약 프로세스 가동 (ChatGPT)...")
    db = SessionLocal()
    
    crawl_bohonara_vulnerability(db)
    crawl_rss_source(db, "보안뉴스", "https://www.boannews.com/media/rss.xml", "보안뉴스 취재팀")
    crawl_rss_source(db, "데일리시큐", "https://www.dailysecu.com/rss/clickTop.xml", "데일리시큐 취재기자")
    
    db.close()
    print("\n🏁 모든 카테고리 데이터 수집 및 종합 요약 저장 완료!")

def fetch_security_news():
    """main.py의 스케줄러에서 호출하는 보안 뉴스 수집 함수"""
    print("🚀 [스케줄러] 정기 보안 뉴스 수집 프로세스 가동...")
    db = SessionLocal()
    try:
        crawl_rss_source(
            db,
            "보안뉴스",
            "https://www.boannews.com/media/rss.xml",
            "보안뉴스 취재팀",
        )
        crawl_rss_source(
            db,
            "데일리시큐",
            "https://www.dailysecu.com/rss/clickTop.xml",
            "데일리시큐 취재기자",
        )
    finally:
        db.close()
    print("🏁 [스케줄러] 정기 보안 뉴스 수집 완료!")

if __name__ == "__main__":
    init_db()
    
    # 2. 나중에 평소에 돌릴 때 (과거 수집이 다 끝나면 위 3줄을 주석 처리하고 아래 주석을 푸세요)
    crawl_and_sync_all()