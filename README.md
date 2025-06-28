# 원광대학교 컴퓨터소프트웨어공학과 학생 상담관리 시스템

WKU Dept. Computer Software Counsel Program

## 📋 프로젝트 개요

원광대학교 컴퓨터소프트웨어공학과 학생들을 위한 종합 상담관리 시스템입니다. 학생들의 다양한 상담 요청을 체계적으로 분류하고 관리하며, 모든 상담 내용을 데이터베이스에 저장하여 지속적인 관리를 제공합니다.

## 🎯 주요 기능

### 회원 관리 시스템
- **🔐 학교 이메일 회원가입**: 원광대학교 이메일(@wku.ac.kr)로만 가입 가능
- **📝 학생 정보 관리**: 학번, 이름, 학년, 연락처 등 체계적 관리
- **🔒 로그인/로그아웃**: 안전한 세션 기반 인증 시스템

### 상담 분야 분류
- **📚 학사관리 (AM)**: 수강신청, 학점관리, 졸업요건, 휴학/복학 절차 등
- **🏫 학교생활 (CL)**: 교내활동, 대인관계, 학습방법, 스트레스 관리 등
- **💼 진로상담 (CC)**: 취업준비, 진로설계, 대학원 진학, 포트폴리오 작성 등
- **🔧 기타 (OT)**: 개인고민, 가족관계, 경제적 어려움 등

### 핵심 기능
- ✅ 학교 이메일 기반 회원가입 및 로그인 시스템
- ✅ 학생 정보 관리 (학번, 이름, 학년, 연락처)
- ✅ 상담 내용 체계적 분류 및 저장
- ✅ 긴급도 5단계 평가 시스템
- ✅ 상담 상태 관리 (접수/진행중/완료/보류)
- ✅ 종합 대시보드 및 통계 분석
- ✅ 검색 및 필터링 기능
- ✅ 후속 관리 추적 시스템
- ✅ 개인정보 보호 및 보안 강화

## 🛠 기술 스택

- **Backend**: Python Flask 2.3.3
- **Database**: SQLite + SQLAlchemy ORM
- **Frontend**: HTML5, Tailwind CSS, JavaScript
- **Styling**: CSS3, Font Awesome Icons
- **Security**: Werkzeug Password Hashing, Session Management

## 📦 설치 및 실행

### 1. 저장소 클론
```bash
git clone https://github.com/saintgo7/wku-cs-counsel.git
cd wku-cs-counsel
```

### 2. 가상환경 생성 및 활성화
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS/Linux
source venv/bin/activate
```

### 3. 의존성 설치
```bash
pip install -r requirements.txt
```

### 4. 애플리케이션 실행
```bash
python app.py
```

### 5. 웹 브라우저에서 접속
```
http://127.0.0.1:5000
```

## 🗄️ 데이터베이스 구조

### Users 테이블 (사용자 정보)
- `id`: 자동 증가 기본키
- `student_id`: 학번 (고유값)
- `name`: 이름
- `email`: 학교 이메일 (@wku.ac.kr)
- `password_hash`: 암호화된 비밀번호
- `grade`: 학년
- `contact`: 연락처
- `created_at`: 가입일시

### Students 테이블 (학생 기본 정보)
- `student_id`: 학번 (기본키)
- `name`: 이름
- `grade`: 학년
- `contact`: 연락처
- `email`: 이메일
- `major`: 전공 (기본값: 컴퓨터소프트웨어공학과)
- `created_date`: 등록일시

### CounselingRecords 테이블 (상담 기록)
- `id`: 자동 증가 기본키
- `student_id`: 학번 (외래키)
- `student_name`: 학생 이름
- `grade`: 학년
- `contact`: 연락처
- `counseling_category`: 상담 분야 (AM/CL/CC/OT)
- `counseling_title`: 상담 제목
- `counseling_content`: 상담 내용
- `counseling_response`: 상담 답변
- `urgency_level`: 긴급도 (1-5)
- `status`: 상담 상태
- `counselor_id`: 상담사 ID
- `created_date`: 등록일시
- `updated_date`: 수정일시
- `follow_up_needed`: 후속 관리 필요 여부

## 🎨 주요 페이지

### 1. 메인 페이지 (`/`)
- 로그인 전: 시스템 소개 및 로그인/회원가입 안내
- 로그인 후: 개인 대시보드 및 상담 현황

### 2. 회원가입 (`/register`)
- 원광대학교 이메일 인증 필수
- 학번, 이름, 학년, 연락처 등 기본 정보 수집

### 3. 로그인 (`/login`)
- 학번과 비밀번호로 로그인
- 세션 기반 인증 관리

### 4. 상담 신청 (`/add`)
- 4개 분야별 상담 신청
- 긴급도 설정 및 후속 관리 옵션

### 5. 상담 관리 (`/manage`)
- 전체 상담 목록 조회
- 필터링 및 검색 기능

### 6. 통계 페이지 (`/statistics`)
- 분야별, 상태별 통계
- 월별 상담 추이 분석

## 🔐 보안 기능

- **이메일 인증**: 원광대학교 이메일(@wku.ac.kr)만 가입 가능
- **비밀번호 암호화**: Werkzeug를 이용한 안전한 비밀번호 해싱
- **세션 관리**: Flask 세션을 통한 안전한 로그인 상태 관리
- **개인정보 보호**: 상담 내용 및 개인정보 안전 보관

## 📱 반응형 디자인

- Tailwind CSS 기반 모바일 최적화
- 태블릿, PC 등 다양한 화면 크기 지원
- 직관적인 사용자 인터페이스

## 🚀 배포 환경

### 개발 환경
- Python 3.8+
- Flask Development Server

### 프로덕션 환경 (권장)
- Gunicorn + Nginx
- PostgreSQL 또는 MySQL
- SSL 인증서 적용

## 📞 지원 및 문의

- **개발자**: saintgo7
- **이메일**: saintgo7@gmail.com
- **GitHub**: https://github.com/saintgo7/wku-cs-counsel

## 📄 라이선스

이 프로젝트는 MIT 라이선스 하에 배포됩니다.

---

**원광대학교 컴퓨터소프트웨어공학과 학생 상담관리 시스템**  
© 2024 All rights reserved.

### 📝 회원가입 방법

1. **회원가입 페이지 접속**: `http://127.0.0.1:5000/register`
2. **필수 정보 입력**:
   - 학번: 8자리 숫자 (예: 20240001)
   - 이름: 실명 입력
   - 학년: 1~4학년 선택
   - 연락처: 휴대폰 번호
   - 이메일: 원광대학교 이메일 (@wku.ac.kr)
   - 비밀번호: 8자 이상 (영문, 숫자, 특수문자 포함 권장)
3. **이메일 인증**: 자동으로 원광대학교 이메일 형식 검증
4. **회원가입 완료** 후 로그인 가능
