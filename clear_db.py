import datetime
import os
import zoneinfo
from database import SecurityNews, SecurityVulnerability, SessionLocal, init_db

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


def delete_news_by_source(source_name="뉴식스"):
    """특정 매체(source) 이름이 포함된 뉴스 데이터를 DB에서 일괄 삭제합니다."""
    db = SessionLocal()
    try:
        # source 또는 author 컬럼에 특정 매체명이 포함되어 있는지 검색
        query = db.query(SecurityNews).filter(
            (SecurityNews.source.like(f"%{source_name}%"))
            | (SecurityNews.author.like(f"%{source_name}%"))
        )

        deleted_count = query.count()

        if deleted_count == 0:
            print(f"ℹ️ [{source_name}] 매체로 저장된 데이터가 없습니다.")
            return

        # 조회된 데이터 일괄 삭제
        query.delete(synchronize_session=False)
        db.commit()
        print(
            f"🗑️ [{source_name}] 관련 기사 총 {deleted_count}건을 성공적으로 삭제했습니다."
        )

    except Exception as e:
        db.rollback()
        print(f"❌ 데이터 삭제 중 오류 발생: {e}")
    finally:
        db.close()


if __name__ == "__main__":
    delete_news_by_source()