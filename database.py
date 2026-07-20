import datetime
import os
from sqlalchemy import Column, DateTime, Integer, String, Text, create_engine, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# 도커 컴포즈 및 Render DB 설정
DATABASE_URL = os.getenv(
    "DATABASE_URL", 
    "postgresql://security_admin:security_password123!@localhost:5432/security_intelligence"
)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# 1. KISA 보호나라 등 기술 취약점 공지 전용 테이블
class SecurityVulnerability(Base):
    __tablename__ = "security_vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    source = Column(String, index=True, default="KISA 보호나라") # 출처 매체
    author = Column(String, index=True, nullable=True)         # 작성자/부서
    title = Column(String, index=True)                          # 제목
    link = Column(String, unique=True)                          # 원본 링크
    content = Column(Text, nullable=True)                       # 본문 내용
    summary = Column(Text, nullable=True)                       # 아카이브용 요약
    cve_code = Column(String, index=True, nullable=True)        # CVE 코드 필드
    published_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

# 2. 보안뉴스, 데일리시큐 등 일반 동향 뉴스 전용 테이블
class SecurityNews(Base):
    __tablename__ = "security_news"

    id = Column(Integer, primary_key=True, index=True)
    source = Column(String, index=True)                         # 출처 매체 (보안뉴스, 데일리시큐 등)
    author = Column(String, index=True, nullable=True)         # 작성자/기자
    title = Column(String, index=True)                          # 제목
    link = Column(String, unique=True)                          # 원본 링크
    content = Column(Text, nullable=True)                       # 본문 내용
    summary = Column(Text, nullable=True)                       # 센터 공유용 요약
    category = Column(String, index=True, default="기타보안", nullable=True) # 💡 AI 카테고리
    published_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class SecurityNotice(Base):
    """KISA 보호나라 보안공지 전용 테이블"""
    __tablename__ = "security_notices"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    link = Column(String(500), nullable=False, unique=True)
    author = Column(String(100), default="KISA 보호나라")
    content = Column(Text, nullable=True)
    posted_date = Column(String(20), nullable=False)  # 예: "2026-07-20"
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    

def init_db():
    Base.metadata.create_all(bind=engine)

    # Render DB 등 기존 DB에 컬럼 안전하게 추가 (데이터 보존)
    with engine.connect() as conn:
        try:
            conn.execute(text("""
                ALTER TABLE security_news 
                ADD COLUMN IF NOT EXISTS category VARCHAR DEFAULT '기타보안';
            """))
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS ix_security_news_category 
                ON security_news (category);
            """))
            conn.commit()
            print("DB 마이그레이션 성공: category 컬럼이 준비되었습니다.")
        except Exception as e:
            print(f"DB 마이그레이션 중 오류 발생: {e}")