import os
from database import SecurityNews, SessionLocal
from openai import OpenAI

# 최신 OpenAI 클라이언트 생성
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


def classify_text_with_ai(title: str, content: str) -> str:
    prompt = f"""
    당신은 정보보안센터의 보안 뉴스 분류 전문가입니다.
    아래 보안 뉴스 기사의 제목과 내용을 분석하여, 가장 적합한 카테고리 하나만 골라 답하세요.

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
            messages=[{"role": "user", "content": prompt}],
            temperature=0.0,
        )
        category = response.choices[0].message.content.strip()
        if category not in ["침해", "해킹", "개인정보", "기타보안"]:
            category = "기타보안"
        return category
    except Exception as e:
        print(f"AI 분류 오류: {e}")
        return "기타보안"


def run_backfill():
    db = SessionLocal()
    try:
        # category가 '기타보안'이거나 Null인 기존 기사만 대상 조회
        target_news = (
            db.query(SecurityNews)
            .filter(
                (SecurityNews.category == "기타보안")
                | (SecurityNews.category == None)
            )
            .all()
        )

        print(
            f"총 {len(target_news)}건의 기존 뉴스 카테고리 재분류 시작..."
        )
        for news in target_news:
            news.category = classify_text_with_ai(news.title, news.content)
            print(f"[{news.id}] {news.title[:20]}... -> {news.category}")

        db.commit()
        print("기존 뉴스 AI 카테고리 재분류 완료!")
    except Exception as e:
        db.rollback()
        print(f"오류 발생: {e}")
    finally:
        db.close()