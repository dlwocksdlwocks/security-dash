import os
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

api_key = os.getenv("OPENAI_API_KEY")
client = OpenAI(api_key=api_key)


def is_security_relevant_with_chatgpt(title, content):
    """
    기사 제목과 내용을 바탕으로 기업/기관 보안 담당자에게 
    실질적으로 필요한 보안 위협/이슈 기사인지 판별합니다.
    """
    # 💡 1차 단순 키워드 노이즈 제거 (API 호출 절약용)
    noise_keywords = ["주재", "동정", "인사", "임명", "동향", "MOU 체결", "개회사", "축사"]
    core_keywords = ["유출", "해킹", "악성코드", "취약점", "랜섬웨어", "침해"]

    # 동정성 키워드가 포함되어 있고, 핵심 보안 키워드가 없다면 AI 호출 없이 바로 제외(False)
    has_noise = any(keyword in title for keyword in noise_keywords)
    has_core = any(keyword in title for keyword in core_keywords)

    if has_noise and not has_core:
        return False

    prompt = f"""
    당신은 기업 정보보안센터의 보안위협 분석 전문가입니다.
    아래 뉴스 기사가 '기업/기관 보안 담당자 및 네트워크/서버 관리자'에게 실질적으로 유의미한 보안 관련 뉴스인지 평가하세요.

    [유의미한 보안 뉴스의 예시 (YES)]
    - 해킹, 침해사고, 랜섬웨어, 악성코드, 정보유출 사고
    - 제로데이, CVE 취약점, 보안 패치 권고
    - 개인정보보호위원회/KISA의 실제 과징금 부과, 유출 제재, 보안 지침 발표
    - 보안 기술, 피싱/스미싱 수법, 보안 솔루션 관련 주요 이슈

    [의미 없는 뉴스의 예시 (NO)]
    - 단순 정부/위원회의 행사, 회의 주재, 단순 인사를 다룬 동정 기사
    - 보안과 직접적 관련이 없는 단순 IT 신제품 출시, 서비스 업데이트
    - 단순 정책 홍보나 인물 동정론

    [응답 규칙]
    - 보안 담당자에게 필독 가치가 있다면 'YES', 단순 행정/동정/무관 기사라면 'NO' 단어 하나만 반환하세요.

    [기사 제목]
    {title}

    [기사 내용]
    {content[:300] if content else ''}
    """
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "너는 보안 가치 평가 전문가야. YES 또는 NO 단 하나만 반환해."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.0
        )
        result = response.choices[0].message.content.strip().upper()
        return "YES" in result
    except Exception as e:
        print(f"⚠️ AI 보안 필터링 중 에러 (기본 통과 처리): {e}")
        return True # 에러 발생 시 기사 누락 방지를 위해 기본 통과