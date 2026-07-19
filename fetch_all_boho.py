import datetime
import urllib.parse
import requests
from bs4 import BeautifulSoup
from openai import OpenAI
# 💡 분리된 취약점 전용 모델(SecurityVulnerability)을 가져옵니다.
from database import SessionLocal, init_db, SecurityVulnerability
import time
import re  # 💡 CVE 코드 추출을 위한 정규식 추가
from dotenv import load_dotenv
import os

load_dotenv()

# OpenAI 클라이언트 초기화
api_key = os.getenv("OPENAI_API_KEY")
client = OpenAI(api_key=api_key)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
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
    # 아카이브 구축용 정밀 프롬프트 유지 (온도 0.2로 세팅)
    prompt = (
        f"출처: {source} ({author})\n"
        f"제목: {title}\n"
        f"본문 내용:\n{content}\n\n"
        f"너는 정보보안센터의 과거 취약점 데이터베이스(DB) 아카이브를 구축하기 위한 보안 전문가야.\n"
        f"나중에 인프라 및 보안 장비 자산 검토 시 빠르게 참고할 수 있도록, 해당 취약점의 '핵심 대상 솔루션/OS'와 '보안 위험 요인'을 중심으로 70글자 내로 아주 짧고 명확하게 요약해줘.\n"
        f"요약 끝에는 반드시 '출처: {source} ({author})'를 명시해줘."
    )
    
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "너는 정보보안센터의 CISO이자 자산 취약점 분석가야. 불필요한 수식어 없이 기술적 팩트와 핵심 위협만 직관적으로 요약하는 전문가야."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"❌ ChatGPT 요약 실패: {e}")
        return "요약 프로세스 일시적 제한"

def fetch_all_bohonara():
    print("🚀 [KISA 보호나라] 과거 취약점 공지 전체 수집 프로세스 가동 (분리형 DB + CVE 매핑)...")
    db = SessionLocal()
    
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

            page_saved_count = 0
            for tr in post_items:
                link_tag = tr.select_one("td.sbj.tal a")
                if not link_tag:
                    continue
                    
                title = link_tag.get_text(strip=True)
                href = link_tag.get('href', '')
                
                # nttId 파라미터 추출
                parsed_url = urllib.parse.urlparse(href)
                params = urllib.parse.parse_qs(parsed_url.query)
                ntt_id = params.get('nttId', [None])[0]
                
                if not ntt_id and 'nttId=' in href:
                    ntt_id = href.split('nttId=')[1].split('&')[0]
                
                if not ntt_id:
                    continue

                full_link = f"https://www.boho.or.kr/kr/bbs/view.do?menuNo=205023&bbsId=B0000302&nttId={ntt_id}"
                
                # 💡 새로 정의한 테이블(SecurityVulnerability)에서 중복 체크
                exists = db.query(SecurityVulnerability).filter(SecurityVulnerability.link.like(f"%nttId={ntt_id}%")).first()
                if exists:
                    print(f"⏭️ nttId {ntt_id}는 이미 DB에 존재하므로 패스합니다.")
                    continue 

                # 상세 본문 크롤링
                content_text = ""
                try:
                    detail_res = requests.get(full_link, headers=HEADERS, timeout=10)
                    detail_res.encoding = 'utf-8'
                    detail_soup = BeautifulSoup(detail_res.text, 'html.parser')
                    
                    view_content = detail_soup.select_one(".bbs_view_container")
                    content_text = view_content.get_text(strip=True)[:2500] if view_content else title
                except Exception:
                    content_text = title
                
                # 💡 제목과 본문에서 CVE 코드 자동 매핑
                cve_code = extract_cve_code([title, content_text])
                
                print(f"📰 새 취약점 발견 (nttId: {ntt_id}) [CVE: {cve_code}]: {title}")
                
                # ChatGPT 요약 수행
                summary = summarize_with_chatgpt(title, content_text, "KISA 보호나라", "KISA 침해사고분석단")
                
                # 💡 SecurityVulnerability 객체에 값 주입
                article = SecurityVulnerability(
                    source="KISA 보호나라",
                    author="KISA 침해사고분석단",
                    title=title,
                    link=full_link,
                    content=content_text,
                    summary=summary,
                    cve_code=cve_code,  # CVE 컬럼 추가됨
                    published_at=datetime.datetime.utcnow()
                )
                db.add(article)
                page_saved_count += 1
                total_saved += 1
                
                time.sleep(0.5)
                
            db.commit()
            print(f"✅ {page}페이지 완료 (이번 페이지에서 {page_saved_count}건 저장됨)")
            page += 1
            
        except Exception as e:
            print(f"❌ {page}페이지 크롤링 도중 에러 발생: {e}")
            break
            
    db.close()
    print(f"\n🏁 수집 전면 완료! 총 {total_saved}건의 데이터가 security_vulnerabilities 테이블에 적재되었습니다.")

if __name__ == "__main__":
    init_db()
    
    # 만약 테이블을 완전히 초기화하고 전체 다 긁어오고 싶을 때 풀어서 사용하세요.
    # db = SessionLocal(); db.query(SecurityVulnerability).delete(); db.commit(); db.close()
    
    fetch_all_bohonara()