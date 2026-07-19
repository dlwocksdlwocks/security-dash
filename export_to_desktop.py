import os
import csv
from database import SessionLocal, SecurityVulnerability

def export_vulnerabilities_to_desktop():
    print("📦 PostgreSQL에서 보호나라 DB 추출을 시작합니다...")
    db = SessionLocal()
    
    try:
        # 1. DB에서 전체 보호나라 취약점 데이터 조회
        items = db.query(SecurityVulnerability).order_by(SecurityVulnerability.id.desc()).all()
        if not items:
            print("❌ DB에 저장된 데이터가 없습니다. 먼저 수집을 진행해 주세요.")
            return

        # 2. 시스템의 '바탕화면(Desktop)' 절대 경로 자동으로 찾기
        desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
        file_path = os.path.join(desktop_path, "보호나라_취약점_아카이브.csv")

        # 3. CSV 파일 작성 (한글 깨짐 방지를 위해 utf-8-sig 인코딩 사용)
        with open(file_path, mode='w', encoding='utf-8-sig', newline='') as f:
            writer = csv.writer(f)
            
            # 헤더 작성
            writer.writerow(['ID', '출처', '작성부서', '제목', 'CVE 코드', '링크', '요약내용', '본문(일부)', '수집일시'])
            
            # 데이터 행 작성
            for item in items:
                writer.writerow([
                    item.id,
                    item.source,
                    item.author,
                    item.title,
                    item.cve_code if item.cve_code else '없음',
                    item.link,
                    item.summary,
                    item.content[:500] + "..." if item.content else "", # 본문은 너무 기니 500자만
                    item.created_at
                ])
                
        print(f"✨ 추출 완료! 바탕화면에서 파일을 확인하세요:\n📍 경로: {file_path}")
        
    except Exception as e:
        print(f"❌ 파일 내보내기 실패: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    export_vulnerabilities_to_desktop()