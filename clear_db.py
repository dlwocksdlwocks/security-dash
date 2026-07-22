import os
import zoneinfo
import datetime
from database import SessionLocal, SecurityVulnerability, SecurityNews, init_db
from crawler import crawl_and_sync_all

KST = zoneinfo.ZoneInfo("Asia/Seoul")

def reset_SecurityNews():
    init_db()
    db = SessionLocal()
    try:
        now_str = datetime.datetime.now(KST).strftime("%Y-%m-%d %H:%M:%S")
        print(f"\n[🧹 {now_str} KST] SecurityNews 테이블 초기화 시작...")
        
        # 기존 News 데이터만 깨끗하게 삭제
        deleted_count = db.query(SecurityNews).delete()
        db.commit()
        print(f"✅ 기존 기사 데이터 {deleted_count}건 삭제 완료!")
    except Exception as e:
        db.rollback()
        print(f"❌ DB 초기화 중 오류 발생: {e}")
    finally:
        db.close()

def reset_SecurityVulnerability():
    """SecurityVulnerability(취약점 정보) 테이블 전용 초기화 함수"""
    init_db()
    db = SessionLocal()
    try:
        print("\n🧹 SecurityVulnerability 테이블 초기화 시작...")
        deleted_count = db.query(SecurityVulnerability).delete()
        db.commit()
        print(f"✅ 기존 취약점 데이터 {deleted_count}건 삭제 완료!")
    except Exception as e:
        db.rollback()
        print(f"❌ DB 초기화 중 오류 발생: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    reset_SecurityVulnerability()