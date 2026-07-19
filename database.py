from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import datetime

# 도커 컴포즈에 설정한 DB 정보와 일치합니다.
DATABASE_URL = "postgresql://security_admin:security_password123!@localhost:5432/security_intelligence"

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
    link = Column(String, unique=True)                           # 원본 링크
    content = Column(Text, nullable=True)                       # 본문 내용
    summary = Column(Text, nullable=True)                       # 아카이브용 요약
    cve_code = Column(String, index=True, nullable=True)        # 💡 CVE 코드 필드 추가
    published_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

# 2. 보안뉴스, 데일리시큐 등 일반 동향 뉴스 전용 테이블
class SecurityNews(Base):
    __tablename__ = "security_news"

    id = Column(Integer, primary_key=True, index=True)
    source = Column(String, index=True)                         # 출처 매체 (보안뉴스, 데일리시큐 등)
    author = Column(String, index=True, nullable=True)         # 작성자/기자
    title = Column(String, index=True)                          # 제목
    link = Column(String, unique=True)                           # 원본 링크
    content = Column(Text, nullable=True)                       # 본문 내용
    summary = Column(Text, nullable=True)                       # 센터 공유용 요약
    published_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

def init_db():
    Base.metadata.create_all(bind=engine)