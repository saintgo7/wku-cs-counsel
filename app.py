from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, send_file
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, date
from enum import Enum
import re
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_for_wku_cs_counseling'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///wku_cs_counseling.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# nl2br 필터 추가
@app.template_filter('nl2br')
def nl2br_filter(text):
    """줄바꿈을 <br> 태그로 변환"""
    if text is None:
        return ''
    return text.replace('\n', '<br>\n')

# 상담 분야 Enum
class CounselingCategory(Enum):
    ACADEMIC = "학업 상담"
    CAREER = "진로 상담"
    CAMPUS_LIFE = "캠퍼스 생활"
    PERSONAL = "개인 상담"
    OTHER = "기타"

# 상담 상태 Enum
class CounselingStatus(Enum):
    PENDING = "대기중"
    IN_PROGRESS = "진행중"
    COMPLETED = "완료"
    CANCELLED = "취소"

# 사용자 역할 Enum
class UserRole(Enum):
    STUDENT = "학생"
    PROFESSOR = "교수"
    ADMIN = "관리자"

# 사용자 모델 (회원가입용)
class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.String(8), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    grade = db.Column(db.Integer)
    contact = db.Column(db.String(20))
    role = db.Column(db.Enum(UserRole), default=UserRole.STUDENT)
    created_date = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def is_wku_email(self):
        """원광대학교 이메일인지 확인"""
        return self.email.endswith('@wku.ac.kr') or self.email.endswith('@wonkwang.ac.kr')
    
    def is_professor(self):
        """교수 권한 확인"""
        return self.role == UserRole.PROFESSOR or self.role == UserRole.ADMIN
    
    def is_admin(self):
        """관리자 권한 확인"""
        return self.role == UserRole.ADMIN

# 학생 정보 모델
class Student(db.Model):
    __tablename__ = 'students'
    
    student_id = db.Column(db.String(8), primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    grade = db.Column(db.Integer)
    contact = db.Column(db.String(20))
    email = db.Column(db.String(100), unique=True, nullable=False)
    major = db.Column(db.String(50), default='컴퓨터소프트웨어공학과')
    created_date = db.Column(db.DateTime, default=datetime.utcnow)
    
    # 관계 설정
    counselings = db.relationship('CounselingRecord', backref='student_info', lazy=True)

# 상담 기록 모델
class CounselingRecord(db.Model):
    __tablename__ = 'counseling_records'
    
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.String(8), db.ForeignKey('students.student_id'), nullable=False)
    student_name = db.Column(db.String(50), nullable=False)
    grade = db.Column(db.Integer)
    contact = db.Column(db.String(20))
    email = db.Column(db.String(100))  # 학생 이메일
    counseling_category = db.Column(db.Enum(CounselingCategory), nullable=False)
    counseling_title = db.Column(db.String(200), nullable=False)
    counseling_content = db.Column(db.Text, nullable=False)
    counseling_response = db.Column(db.Text)  # 기존 응답 필드
    professor_response = db.Column(db.Text)   # 교수 응답
    response_date = db.Column(db.DateTime)    # 응답 날짜
    urgency_level = db.Column(db.Integer, default=3)
    status = db.Column(db.Enum(CounselingStatus), default=CounselingStatus.PENDING)
    counselor_id = db.Column(db.String(20))
    created_date = db.Column(db.DateTime, default=datetime.utcnow)
    updated_date = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    follow_up_needed = db.Column(db.Boolean, default=False)
    follow_up_date = db.Column(db.DateTime)
    satisfaction_score = db.Column(db.Integer)
    notes = db.Column(db.Text)
    admin_memo = db.Column(db.Text)  # 관리자 메모
    
    def get_category_display(self):
        return self.counseling_category.value if self.counseling_category else ""
    
    def get_status_display(self):
        return self.status.value if self.status else ""
    
    def get_urgency_text(self):
        urgency_map = {
            1: "매우 낮음",
            2: "낮음", 
            3: "보통",
            4: "높음",
            5: "매우 높음"
        }
        return urgency_map.get(self.urgency_level, "보통")
    
    def get_status_class(self):
        status_class_map = {
            CounselingStatus.PENDING: "warning",
            CounselingStatus.IN_PROGRESS: "info", 
            CounselingStatus.COMPLETED: "success",
            CounselingStatus.CANCELLED: "danger"
        }
        return status_class_map.get(self.status, "primary")
    
    def get_category_class(self):
        category_class_map = {
            CounselingCategory.ACADEMIC: "info",        # 학업 상담 - 파란색
            CounselingCategory.CAREER: "warning",       # 진로 상담 - 노란색
            CounselingCategory.CAMPUS_LIFE: "success",  # 캠퍼스 생활 - 초록색
            CounselingCategory.PERSONAL: "primary",     # 개인 상담 - 보라색
            CounselingCategory.OTHER: "secondary"       # 기타 - 회색
        }
        return category_class_map.get(self.counseling_category, "secondary")
    
    def get_category_name(self):
        return self.counseling_category.value

def validate_wku_email(email):
    """원광대학교 이메일 유효성 검사"""
    return email.endswith('@wku.ac.kr')

def validate_student_id(student_id):
    """학번 유효성 검사 (8자리 숫자)"""
    return re.match(r'^\d{8}$', student_id) is not None

# 로그인 확인 데코레이터
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('로그인이 필요합니다.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# 교수 권한 확인 데코레이터
def professor_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('로그인이 필요합니다.', 'warning')
            return redirect(url_for('login'))
        
        user = db.session.get(User, session['user_id'])
        if not user or not user.is_professor():
            flash('교수 권한이 필요합니다.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# 관리자 권한 확인 데코레이터
def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('로그인이 필요합니다.', 'warning')
            return redirect(url_for('admin_login'))
        
        user = db.session.get(User, session['user_id'])
        if not user or not user.is_admin():
            flash('관리자 권한이 필요합니다.', 'error')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# 애플리케이션 컨텍스트에서 테이블 생성 및 기본 데이터 생성
def create_default_data():
    """기본 관리자 계정 및 테스트 데이터 생성"""
    try:
        # 관리자 계정 생성
        admin = User.query.filter_by(student_id='admin').first()
        if not admin:
            # 이메일 중복 확인
            existing_admin_email = User.query.filter_by(email='admin@wku.ac.kr').first()
            if existing_admin_email:
                print("관리자 이메일이 이미 존재합니다. 기존 계정을 확인하세요.")
            else:
                admin = User(
                    student_id='admin',
                    name='시스템 관리자',
                    email='admin@wku.ac.kr',
                    role=UserRole.ADMIN
                )
                admin.set_password('admin123')
                db.session.add(admin)
                db.session.commit()
                print("기본 관리자 계정이 생성되었습니다. (ID: admin, PW: admin123)")
        
        # 테스트 교수 계정 생성
        professor = User.query.filter_by(student_id='PROF001').first()
        if not professor:
            existing_prof_email = User.query.filter_by(email='prof001@wku.ac.kr').first()
            if not existing_prof_email:
                professor = User(
                    student_id='PROF001',
                    name='김교수',
                    email='prof001@wku.ac.kr',
                    role=UserRole.PROFESSOR
                )
                professor.set_password('testpass123')
                db.session.add(professor)
                db.session.commit()
                print("테스트 교수 계정이 생성되었습니다. (ID: PROF001, PW: testpass123)")
        
        # 테스트 학생 계정 생성
        student = User.query.filter_by(student_id='STU001').first()
        if not student:
            existing_stu_email = User.query.filter_by(email='stu001@wku.ac.kr').first()
            if not existing_stu_email:
                student = User(
                    student_id='STU001',
                    name='김학생',
                    email='stu001@wku.ac.kr',
                    grade=3,
                    role=UserRole.STUDENT
                )
                student.set_password('testpass123')
                db.session.add(student)
                db.session.commit()
                print("테스트 학생 계정이 생성되었습니다. (ID: STU001, PW: testpass123)")
        
    except Exception as e:
        db.session.rollback()
        print(f"기본 데이터 생성 중 오류: {str(e)}")

with app.app_context():
    db.create_all()
    create_default_data()

# 라우트 정의
@app.route('/')
def index():
    # 대시보드 데이터 처리 제거 - 단순한 첫 화면으로 변경
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        student_id = request.form['student_id'].strip()
        name = request.form['name'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        grade = request.form.get('grade', type=int)
        contact = request.form.get('contact', '').strip()
        
        # 유효성 검사
        if not validate_student_id(student_id):
            flash('학번은 8자리 숫자여야 합니다.', 'error')
            return render_template('register.html')
        
        if not validate_wku_email(email):
            flash('원광대학교 이메일(@wku.ac.kr)만 사용 가능합니다.', 'error')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('비밀번호가 일치하지 않습니다.', 'error')
            return render_template('register.html')
        
        if len(password) < 6:
            flash('비밀번호는 최소 6자리 이상이어야 합니다.', 'error')
            return render_template('register.html')
        
        # 중복 검사
        if User.query.filter_by(student_id=student_id).first():
            flash('이미 등록된 학번입니다.', 'error')
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            flash('이미 등록된 이메일입니다.', 'error')
            return render_template('register.html')
        
        # 사용자 생성
        user = User(
            student_id=student_id,
            name=name,
            email=email,
            password_hash=generate_password_hash(password),
            grade=grade,
            contact=contact
        )
        
        # 학생 정보도 함께 생성
        student = Student(
            student_id=student_id,
            name=name,
            email=email,
            grade=grade,
            contact=contact
        )
        
        try:
            db.session.add(user)
            db.session.add(student)
            db.session.commit()
            flash('회원가입이 완료되었습니다. 로그인해주세요.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('회원가입 중 오류가 발생했습니다. 다시 시도해주세요.', 'error')
            return render_template('register.html')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        student_id = request.form['student_id']
        password = request.form['password']
        
        user = User.query.filter_by(student_id=student_id).first()
        
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['student_id'] = user.student_id
            session['user_name'] = user.name
            session['is_professor'] = user.is_professor()
            flash(f'{user.name}님, 환영합니다!', 'success')
            
            # 사용자 역할에 따라 적절한 페이지로 리다이렉트
            if user.is_admin():
                return redirect(url_for('admin_dashboard'))
            elif user.is_professor():
                return redirect(url_for('professor_dashboard'))
            else:
                # 일반 학생은 상담 관리 페이지로
                return redirect(url_for('manage_counselings'))
        else:
            flash('학번 또는 비밀번호가 올바르지 않습니다.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('로그아웃되었습니다.', 'info')
    return redirect(url_for('index'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = User.query.filter_by(student_id=session['student_id']).first()
    if not user:
        flash('사용자 정보를 찾을 수 없습니다.', 'error')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        # 프로필 업데이트
        name = request.form['name'].strip()
        email = request.form['email'].strip()
        grade = request.form.get('grade', type=int)
        contact = request.form.get('contact', '').strip()
        
        # 이메일 변경 시 유효성 검사
        if email != user.email:
            if not validate_wku_email(email):
                flash('원광대학교 이메일(@wku.ac.kr)만 사용 가능합니다.', 'error')
                return render_template('profile.html', user=user)
            
            # 이메일 중복 검사
            if User.query.filter_by(email=email).first():
                flash('이미 등록된 이메일입니다.', 'error')
                return render_template('profile.html', user=user)
        
        # 비밀번호 변경
        current_password = request.form.get('current_password', '').strip()
        new_password = request.form.get('new_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        
        if new_password:
            if not current_password:
                flash('현재 비밀번호를 입력해주세요.', 'error')
                return render_template('profile.html', user=user)
            
            if not user.check_password(current_password):
                flash('현재 비밀번호가 올바르지 않습니다.', 'error')
                return render_template('profile.html', user=user)
            
            if new_password != confirm_password:
                flash('새 비밀번호가 일치하지 않습니다.', 'error')
                return render_template('profile.html', user=user)
            
            if len(new_password) < 6:
                flash('비밀번호는 최소 6자리 이상이어야 합니다.', 'error')
                return render_template('profile.html', user=user)
            
            user.set_password(new_password)
        
        # 정보 업데이트
        user.name = name
        user.email = email
        user.grade = grade
        user.contact = contact
        
        # 학생 정보도 업데이트
        student = Student.query.filter_by(student_id=user.student_id).first()
        if student:
            student.name = name
            student.email = email
            student.grade = grade
            student.contact = contact
        
        db.session.commit()
        
        # 세션 정보 업데이트
        session['user_name'] = name
        
        flash('프로필이 성공적으로 업데이트되었습니다.', 'success')
        return redirect(url_for('profile'))
    
    # 사용자 상담 통계 계산
    user_stats = {
        'total': CounselingRecord.query.filter_by(student_id=user.student_id).count(),
        'pending': CounselingRecord.query.filter_by(
            student_id=user.student_id, 
            status=CounselingStatus.PENDING
        ).count() + CounselingRecord.query.filter_by(
            student_id=user.student_id, 
            status=CounselingStatus.IN_PROGRESS
        ).count(),
        'completed': CounselingRecord.query.filter_by(
            student_id=user.student_id, 
            status=CounselingStatus.COMPLETED
        ).count()
    }
    
    # 최근 상담 목록
    recent_counselings = CounselingRecord.query.filter_by(
        student_id=user.student_id
    ).order_by(CounselingRecord.created_date.desc()).limit(5).all()
    
    # 카테고리별 통계
    category_stats = {}
    for category in CounselingCategory:
        count = CounselingRecord.query.filter_by(
            student_id=user.student_id,
            counseling_category=category
        ).count()
        category_stats[category.name] = count
    
    # 상태별 통계
    status_stats = {}
    for status in CounselingStatus:
        count = CounselingRecord.query.filter_by(
            student_id=user.student_id,
            status=status
        ).count()
        status_stats[status.name] = count
    
    # 총 상담 건수
    total_counselings = user_stats['total']
    
    # 활동 점수 계산 (간단한 예시)
    activity_score = total_counselings * 10 + user_stats['completed'] * 5
    
    return render_template('profile.html', 
                         user=user, 
                         user_stats=user_stats,
                         recent_counselings=recent_counselings,
                         category_stats=category_stats,
                         status_stats=status_stats,
                         total_counselings=total_counselings,
                         activity_score=activity_score)

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_counseling():
    if request.method == 'POST':
        # 현재 로그인된 사용자 정보 가져오기
        user = db.session.get(User, session['user_id'])
        
        # 학생 정보 확인/생성
        student = Student.query.filter_by(student_id=user.student_id).first()
        if not student:
            student = Student(
                student_id=user.student_id,
                name=user.name,
                grade=user.grade,
                contact=user.contact,
                email=user.email
            )
            db.session.add(student)
        
        # 상담 정보 수집
        category_code = request.form['counseling_category']
        # 카테고리 코드를 Enum으로 변환 (안전한 방법)
        try:
            counseling_category = CounselingCategory[category_code]
        except KeyError:
            flash(f'유효하지 않은 상담 분야입니다: {category_code}', 'error')
            return render_template('add.html')
        counseling_title = request.form['counseling_title']
        counseling_content = request.form['counseling_content']
        urgency_level = int(request.form['urgency_level'])
        
        # 상담 기록 생성
        counseling = CounselingRecord(
            student_id=user.student_id,
            student_name=user.name,
            grade=user.grade,
            contact=user.contact,
            counseling_category=counseling_category,
            counseling_title=counseling_title,
            counseling_content=counseling_content,
            urgency_level=urgency_level
        )
        
        try:
            db.session.add(counseling)
            db.session.commit()
            flash('상담이 성공적으로 등록되었습니다.', 'success')
            return redirect(url_for('manage_counselings'))
        except Exception as e:
            db.session.rollback()
            flash('상담 등록 중 오류가 발생했습니다.', 'error')
    
    return render_template('add.html')

@app.route('/view/<int:counseling_id>')
@login_required
def view_counseling(counseling_id):
    counseling = db.session.get(CounselingRecord, counseling_id)
    if not counseling:
        flash('상담 기록을 찾을 수 없습니다.', 'error')
        return redirect(url_for('index'))
    
    # 본인의 상담이거나 교수 권한이 있는 경우에만 접근 가능
    current_user = db.session.get(User, session['user_id'])
    if counseling.student_id != session.get('student_id') and not current_user.is_professor():
        flash('접근 권한이 없습니다.', 'error')
        return redirect(url_for('index'))
    
    return render_template('view.html', counseling=counseling)

@app.route('/update_status/<int:counseling_id>', methods=['POST'])
@login_required
def update_status(counseling_id):
    counseling = db.session.get(CounselingRecord, counseling_id)
    if not counseling:
        flash('상담 기록을 찾을 수 없습니다.', 'error')
        return redirect(url_for('index'))
    
    try:
        # 상태 업데이트
        status_code = request.form.get('status')
        if status_code:
            try:
                counseling.status = getattr(CounselingStatus, status_code)
            except AttributeError:
                flash('잘못된 상태 코드입니다.', 'error')
                return redirect(url_for('view_counseling', counseling_id=counseling_id))
        
        # 상담 답변 업데이트
        response_content = request.form.get('response', '').strip()
        if response_content:
            counseling.counseling_response = response_content
            counseling.response_date = datetime.utcnow()
        
        # 후속 관리 설정
        counseling.follow_up_needed = 'follow_up' in request.form
        if counseling.follow_up_needed and request.form.get('follow_up_date'):
            try:
                follow_up_date_str = request.form['follow_up_date']
                counseling.follow_up_date = datetime.strptime(follow_up_date_str, '%Y-%m-%d')
            except ValueError:
                flash('잘못된 날짜 형식입니다.', 'error')
        
        # 업데이트 시간 갱신
        counseling.updated_date = datetime.utcnow()
        
        db.session.commit()
        flash('상담 상태가 성공적으로 업데이트되었습니다.', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'상태 업데이트 중 오류가 발생했습니다: {str(e)}', 'error')
        print(f"Error in update_status: {str(e)}")  # 디버깅용 로그
    
    return redirect(url_for('view_counseling', counseling_id=counseling_id))

@app.route('/manage')
@login_required
def manage_counselings():
    # 현재는 본인의 상담만 관리 가능
    student_id = session.get('student_id')
    
    # 필터링 파라미터
    category_filter = request.args.get('category')
    status_filter = request.args.get('status')
    
    query = CounselingRecord.query.filter_by(student_id=student_id)
    
    if category_filter:
        query = query.filter_by(counseling_category=getattr(CounselingCategory, category_filter))
    
    if status_filter:
        query = query.filter_by(status=getattr(CounselingStatus, status_filter))
    
    counselings = query.order_by(CounselingRecord.created_date.desc()).all()
    
    return render_template('manage.html', 
                         counselings=counselings,
                         categories=CounselingCategory,
                         statuses=CounselingStatus)

@app.route('/search')
@login_required
def search():
    query = request.args.get('query', '')
    category_filter = request.args.get('category')
    
    if query:
        # 본인의 상담에서만 검색
        student_id = session.get('student_id')
        search_query = CounselingRecord.query.filter_by(student_id=student_id)
        
        search_query = search_query.filter(
            db.or_(
                CounselingRecord.counseling_title.contains(query),
                CounselingRecord.counseling_content.contains(query)
            )
        )
        
        if category_filter:
            search_query = search_query.filter_by(counseling_category=getattr(CounselingCategory, category_filter))
        
        results = search_query.order_by(CounselingRecord.created_date.desc()).all()
    else:
        results = []
    
    return render_template('search.html', 
                         results=results, 
                         query=query,
                         categories=CounselingCategory)

@app.route('/search_counselings')
@login_required
def search_counselings():
    """상담 검색 API 엔드포인트"""
    query = request.args.get('query', '').strip()
    category = request.args.get('category', '')
    
    if not query:
        return jsonify({'results': []})
    
    # 본인의 상담에서만 검색
    student_id = session.get('student_id')
    search_query = CounselingRecord.query.filter_by(student_id=student_id)
    
    # 제목과 내용에서 검색
    search_query = search_query.filter(
        db.or_(
            CounselingRecord.counseling_title.contains(query),
            CounselingRecord.counseling_content.contains(query)
        )
    )
    
    # 카테고리 필터 적용
    if category and category != 'all':
        try:
            category_enum = getattr(CounselingCategory, category)
            search_query = search_query.filter_by(counseling_category=category_enum)
        except AttributeError:
            pass
    
    results = search_query.order_by(CounselingRecord.created_date.desc()).limit(10).all()
    
    # JSON 형태로 결과 반환
    result_data = []
    for counseling in results:
        result_data.append({
            'id': counseling.id,
            'title': counseling.counseling_title,
            'category': counseling.counseling_category.value,
            'status': counseling.status.value,
            'created_date': counseling.created_date.strftime('%Y-%m-%d'),
            'urgency_level': counseling.urgency_level
        })
    
    return jsonify({'results': result_data})

@app.route('/statistics')
@login_required
def statistics():
    """통계 페이지 - 교수/관리자만 접근 가능"""
    # 권한 체크 - 교수 또는 관리자만 접근 가능
    user = db.session.get(User, session['user_id'])
    if not user or (user.role != UserRole.PROFESSOR and user.role != UserRole.ADMIN):
        flash('교수 또는 관리자 권한이 필요합니다.', 'error')
        return redirect(url_for('index'))
    
    # 기본 통계 - 관리자는 전체, 교수는 자신이 상담한 것만
    if user.is_admin():
        # 관리자는 전체 통계
        base_query = CounselingRecord.query
    else:
        # 교수는 자신이 상담한 내역만
        base_query = CounselingRecord.query.filter_by(counselor_id=user.student_id)
    
    total_counselings = base_query.count()
    completed_counselings = base_query.filter_by(status=CounselingStatus.COMPLETED).count()
    pending_counselings = base_query.filter_by(status=CounselingStatus.PENDING).count()
    in_progress_counselings = base_query.filter_by(status=CounselingStatus.IN_PROGRESS).count()
    cancelled_counselings = base_query.filter_by(status=CounselingStatus.CANCELLED).count()
    
    # 분야별 통계
    category_stats = {}
    category_detail_stats = {}
    for category in CounselingCategory:
        count = base_query.filter_by(counseling_category=category).count()
        category_stats[category.name] = count
        
        # 분야별 상태별 통계
        category_detail_stats[category.name] = {}
        for status in CounselingStatus:
            status_count = base_query.filter_by(
                counseling_category=category,
                status=status
            ).count()
            category_detail_stats[category.name][status.name] = status_count
    
    # 긴급도별 통계 - 템플릿에서 요구하는 형식으로 변경
    urgency_stats = []
    urgency_completed_stats = {}
    for level in range(1, 6):  # 1~5 긴급도
        count = base_query.filter_by(urgency_level=level).count()
        completed_count = base_query.filter_by(
            urgency_level=level,
            status=CounselingStatus.COMPLETED
        ).count()
        
        # 템플릿에서 사용하는 객체 형태로 생성
        urgency_stats.append({
            'level': level,
            'count': count,
            'percentage': round((count / total_counselings * 100) if total_counselings > 0 else 0, 1)
        })
        urgency_completed_stats[level] = completed_count
    
    # 월별 통계 (최근 12개월)
    monthly_stats = {}
    current_date = datetime.now()
    for i in range(12):
        if current_date.month - i <= 0:
            month = current_date.month - i + 12
            year = current_date.year - 1
        else:
            month = current_date.month - i
            year = current_date.year
        
        month_start = datetime(year, month, 1)
        if month == 12:
            month_end = datetime(year + 1, 1, 1)
        else:
            month_end = datetime(year, month + 1, 1)
        
        month_count = base_query.filter(
            CounselingRecord.created_date >= month_start,
            CounselingRecord.created_date < month_end
        ).count()
        
        monthly_stats[month_start.strftime('%Y-%m')] = month_count
    
    # 긴급 상담 목록 (레벨 4-5)
    urgent_counselings = base_query.filter(
        CounselingRecord.urgency_level >= 4
    ).order_by(CounselingRecord.urgency_level.desc(), CounselingRecord.created_date.desc()).limit(10).all()
    
    # 최근 상담 목록
    recent_counselings = base_query.order_by(
        CounselingRecord.created_date.desc()
    ).limit(10).all()
    
    # 학년별 통계 - 템플릿에서 요구하는 형식으로 변경
    grade_stats = []
    for grade in range(1, 5):
        count = base_query.filter_by(grade=grade).count()
        percentage = round((count / total_counselings * 100) if total_counselings > 0 else 0, 1)
        grade_stats.append({
            'grade': grade,
            'total': count,
            'percentage': percentage
        })
    
    # 교수별 통계 - 관리자만 볼 수 있음
    professor_stats = []
    if user.is_admin():
        professors = User.query.filter_by(role=UserRole.PROFESSOR).all()
        for professor in professors:
            prof_total = CounselingRecord.query.filter_by(counselor_id=professor.student_id).count()
            prof_completed = CounselingRecord.query.filter_by(
                counselor_id=professor.student_id,
                status=CounselingStatus.COMPLETED
            ).count()
            completion_rate = round((prof_completed / prof_total * 100) if prof_total > 0 else 0, 1)
            
            professor_stats.append({
                'name': professor.name,
                'total': prof_total,
                'completed': prof_completed,
                'completion_rate': completion_rate
            })
    
    # 기간 필터링 정보 (현재는 기본값)
    current_filters = {
        'start_date': '',
        'end_date': ''
    }
    
    stats = {
        'total_counselings': total_counselings,
        'completed_counselings': completed_counselings,
        'pending_counselings': pending_counselings,
        'in_progress_counselings': in_progress_counselings,
        'cancelled_counselings': cancelled_counselings,
        'category_stats': category_stats,
        'category_detail_stats': category_detail_stats,
        'urgency_stats': urgency_stats,
        'urgency_completed_stats': urgency_completed_stats,
        'monthly_stats': monthly_stats,
        'grade_stats': grade_stats,
        'professor_stats': professor_stats
    }
    
    return render_template('statistics.html',
                         stats=stats,
                         urgent_counselings=urgent_counselings,
                         recent_counselings=recent_counselings,
                         current_filters=current_filters,
                         total_counselings=total_counselings,
                         completed_counselings=completed_counselings,
                         pending_counselings=pending_counselings,
                         in_progress_counselings=in_progress_counselings,
                         cancelled_counselings=cancelled_counselings,
                         category_stats=category_stats,
                         category_detail_stats=category_detail_stats,
                         urgency_stats=urgency_stats,
                         urgency_completed_stats=urgency_completed_stats,
                         monthly_stats=monthly_stats,
                         grade_stats=grade_stats,
                         user_role=user.role.value)

# 교수 관리자 페이지 라우트들
@app.route('/professor')
@professor_required
def professor_dashboard():
    """교수 대시보드 - 모든 상담 현황 조회"""
    # 전체 상담 통계
    total_counselings = CounselingRecord.query.count()
    pending_counselings = CounselingRecord.query.filter_by(status=CounselingStatus.PENDING).count()
    in_progress_counselings = CounselingRecord.query.filter_by(status=CounselingStatus.IN_PROGRESS).count()
    completed_counselings = CounselingRecord.query.filter_by(status=CounselingStatus.COMPLETED).count()
    
    # 긴급도가 높은 상담 (4, 5)
    urgent_counselings = CounselingRecord.query.filter(
        CounselingRecord.urgency_level >= 4,
        CounselingRecord.status.in_([CounselingStatus.PENDING, CounselingStatus.IN_PROGRESS])
    ).order_by(CounselingRecord.urgency_level.desc(), CounselingRecord.created_date.asc()).all()
    
    # 최근 상담 목록
    recent_counselings = CounselingRecord.query.order_by(
        CounselingRecord.created_date.desc()
    ).limit(10).all()
    
    # 분야별 통계
    category_stats = {}
    for category in CounselingCategory:
        count = CounselingRecord.query.filter_by(counseling_category=category).count()
        category_stats[category.value] = count
    
    return render_template('professor_dashboard.html',
                         total_counselings=total_counselings,
                         pending_counselings=pending_counselings,
                         in_progress_counselings=in_progress_counselings,
                         completed_counselings=completed_counselings,
                         urgent_counselings=urgent_counselings,
                         recent_counselings=recent_counselings,
                         category_stats=category_stats)

@app.route('/professor/counselings')
@professor_required
def professor_counselings():
    """교수용 상담 목록 관리"""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    # 필터링
    category_filter = request.args.get('category')
    status_filter = request.args.get('status')
    urgency_filter = request.args.get('urgency')
    search_query = request.args.get('search', '').strip()
    
    query = CounselingRecord.query
    
    if category_filter:
        query = query.filter_by(counseling_category=getattr(CounselingCategory, category_filter))
    
    if status_filter:
        query = query.filter_by(status=getattr(CounselingStatus, status_filter))
    
    if urgency_filter:
        query = query.filter_by(urgency_level=int(urgency_filter))
    
    if search_query:
        query = query.filter(
            db.or_(
                CounselingRecord.student_name.contains(search_query),
                CounselingRecord.counseling_title.contains(search_query),
                CounselingRecord.counseling_content.contains(search_query)
            )
        )
    
    counselings = query.order_by(
        CounselingRecord.urgency_level.desc(),
        CounselingRecord.created_date.desc()
    ).paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template('professor_counselings.html',
                         counselings=counselings,
                         categories=CounselingCategory,
                         statuses=CounselingStatus,
                         current_filters={
                             'category': category_filter,
                             'status': status_filter,
                             'urgency': urgency_filter,
                             'search': search_query
                         })

@app.route('/professor/counseling/<int:counseling_id>')
@professor_required
def professor_view_counseling(counseling_id):
    """교수용 상담 상세 보기 및 답변"""
    counseling = db.session.get(CounselingRecord, counseling_id)
    if not counseling:
        flash('상담 기록을 찾을 수 없습니다.', 'error')
        return redirect(url_for('professor_counselings'))
    
    return render_template('professor_counseling_detail.html', counseling=counseling)

@app.route('/professor/counseling/<int:counseling_id>/respond', methods=['POST'])
@professor_required
def professor_respond_counseling(counseling_id):
    """교수 상담 답변 처리"""
    counseling = db.session.get(CounselingRecord, counseling_id)
    if not counseling:
        flash('상담 기록을 찾을 수 없습니다.', 'error')
        return redirect(url_for('professor_counselings'))
    
    try:
        # 답변 내용 저장
        response_content = request.form.get('response', '').strip()
        if response_content:
            counseling.counseling_response = response_content
            counseling.response_date = datetime.utcnow()  # 응답 날짜 설정
        
        # 상태 업데이트
        status_code = request.form.get('status')
        if status_code:
            try:
                counseling.status = getattr(CounselingStatus, status_code)
            except AttributeError:
                # 잘못된 상태 코드인 경우 기본값 설정
                counseling.status = CounselingStatus.IN_PROGRESS
        
        # 상담자 ID 설정
        current_user = db.session.get(User, session['user_id'])
        counseling.counselor_id = current_user.student_id
        
        # 후속 관리 설정
        counseling.follow_up_needed = 'follow_up' in request.form
        if counseling.follow_up_needed and request.form.get('follow_up_date'):
            try:
                # DateTime 객체로 변환 (시간은 자정으로 설정)
                follow_up_date_str = request.form['follow_up_date']
                counseling.follow_up_date = datetime.strptime(follow_up_date_str, '%Y-%m-%d')
            except ValueError:
                # 날짜 형식이 잘못된 경우 무시
                pass
        
        # 메모 추가
        notes = request.form.get('notes', '').strip()
        if notes:
            current_time = datetime.now().strftime('%Y-%m-%d %H:%M')
            if counseling.notes:
                counseling.notes += f"\n\n[{current_time}] {current_user.name}: {notes}"
            else:
                counseling.notes = f"[{current_time}] {current_user.name}: {notes}"
        
        # 업데이트 시간 갱신
        counseling.updated_date = datetime.utcnow()
        
        db.session.commit()
        flash('상담 답변이 성공적으로 저장되었습니다.', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'답변 저장 중 오류가 발생했습니다: {str(e)}', 'error')
        print(f"Error in professor_respond_counseling: {str(e)}")  # 디버깅용 로그
    
    return redirect(url_for('professor_view_counseling', counseling_id=counseling_id))

@app.route('/professor/statistics')
@professor_required
def professor_statistics():
    """교수용 전체 상담 통계"""
    # 현재 사용자 확인
    user = db.session.get(User, session['user_id'])
    
    # 기본 통계 - 관리자는 전체, 교수는 자신이 담당한 것만
    if user.is_admin():
        # 관리자는 전체 통계
        base_query = CounselingRecord.query
    else:
        # 교수는 자신이 담당한 상담만
        base_query = CounselingRecord.query.filter_by(counselor_id=user.student_id)
    
    total_counselings = base_query.count()
    completed_counselings = base_query.filter_by(status=CounselingStatus.COMPLETED).count()
    pending_counselings = base_query.filter_by(status=CounselingStatus.PENDING).count()
    in_progress_counselings = base_query.filter_by(status=CounselingStatus.IN_PROGRESS).count()
    cancelled_counselings = base_query.filter_by(status=CounselingStatus.CANCELLED).count()
    
    # 분야별 통계
    category_stats = {}
    for category in CounselingCategory:
        count = base_query.filter_by(counseling_category=category).count()
        category_stats[category.name] = count
    
    # 분야별 상세 통계 (상태별)
    category_detail_stats = {}
    for category in CounselingCategory:
        category_detail_stats[category.name] = {
            'PENDING': base_query.filter_by(counseling_category=category, status=CounselingStatus.PENDING).count(),
            'IN_PROGRESS': base_query.filter_by(counseling_category=category, status=CounselingStatus.IN_PROGRESS).count(),
            'COMPLETED': base_query.filter_by(counseling_category=category, status=CounselingStatus.COMPLETED).count(),
            'CANCELLED': base_query.filter_by(counseling_category=category, status=CounselingStatus.CANCELLED).count()
        }
    
    # 긴급도별 통계
    urgency_stats = {}
    urgency_completed_stats = {}
    for level in range(1, 6):
        count = base_query.filter_by(urgency_level=level).count()
        completed_count = base_query.filter_by(urgency_level=level, status=CounselingStatus.COMPLETED).count()
        urgency_stats[level] = count
        urgency_completed_stats[level] = completed_count
    
    # 긴급 상담 목록 (레벨 4-5)
    urgent_counselings = base_query.filter(
        CounselingRecord.urgency_level >= 4
    ).order_by(CounselingRecord.urgency_level.desc(), CounselingRecord.created_date.desc()).limit(10).all()
    
    # 월별 통계 (최근 12개월) - 템플릿에서 사용하는 형식으로 변환
    monthly_stats_list = []
    monthly_stats = {}
    current_date = datetime.now()
    for i in range(12):
        if current_date.month - i <= 0:
            month = current_date.month - i + 12
            year = current_date.year - 1
        else:
            month = current_date.month - i
            year = current_date.year
        
        month_start = datetime(year, month, 1)
        if month == 12:
            month_end = datetime(year + 1, 1, 1)
        else:
            month_end = datetime(year, month + 1, 1)
        
        month_count = base_query.filter(
            CounselingRecord.created_date >= month_start,
            CounselingRecord.created_date < month_end
        ).count()
        
        month_key = month_start.strftime('%Y-%m')
        monthly_stats_list.append({
            'month': month_key,
            'count': month_count
        })
        monthly_stats[month_key] = month_count
    
    monthly_stats_list.reverse()  # 오래된 순서부터 표시
    
    # 학년별 통계
    grade_stats = {}
    for grade in range(1, 5):
        count = base_query.filter_by(grade=grade).count()
        grade_stats[f"{grade}학년"] = count
    
    # 최근 상담 목록
    recent_counselings = base_query.order_by(
        CounselingRecord.created_date.desc()
    ).limit(10).all()
    
    stats = {
        'total_counselings': total_counselings,
        'completed_counselings': completed_counselings,
        'pending_counselings': pending_counselings,
        'in_progress_counselings': in_progress_counselings,
        'cancelled_counselings': cancelled_counselings,
        'category_stats': category_stats,
        'category_detail_stats': category_detail_stats,
        'urgency_stats': urgency_stats,
        'urgency_completed_stats': urgency_completed_stats,
        'monthly_stats': monthly_stats,  # 딕셔너리 형태 유지
        'grade_stats': grade_stats
    }
    
    # 템플릿에서 사용하는 변수명과 일치시키기
    return render_template('professor_statistics.html', 
                         stats=stats, 
                         urgent_counselings=urgent_counselings,
                         recent_counselings=recent_counselings,
                         is_professor=True,
                         total_counselings=total_counselings,
                         completed_counselings=completed_counselings,
                         pending_counselings=pending_counselings,
                         in_progress_counselings=in_progress_counselings,
                         cancelled_counselings=cancelled_counselings,
                         category_stats=category_stats,
                         category_detail_stats=category_detail_stats,
                         urgency_stats=urgency_stats,
                         urgency_completed_stats=urgency_completed_stats,
                         monthly_stats=monthly_stats,  # 딕셔너리 형태로 전달
                         grade_stats=grade_stats,
                         user_role=user.role.value)

# 관리자 로그인 라우트
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """관리자 전용 로그인"""
    if request.method == 'POST':
        student_id = request.form.get('student_id', '').strip()
        password = request.form.get('password', '').strip()
        
        if not student_id or not password:
            flash('학번과 비밀번호를 모두 입력해주세요.', 'error')
            return render_template('admin_login.html')
        
        user = User.query.filter_by(student_id=student_id).first()
        
        if user and user.check_password(password):
            if user.is_admin():
                session['user_id'] = user.id
                session['student_id'] = user.student_id
                session['user_name'] = user.name
                session['role'] = user.role.value
                session['is_admin'] = True
                session['is_professor'] = user.is_professor()
                flash(f'{user.name} 관리자님, 환영합니다!', 'success')
                return redirect(url_for('admin_dashboard'))
            else:
                flash('관리자 권한이 없습니다.', 'error')
        else:
            flash('학번 또는 비밀번호가 잘못되었습니다.', 'error')
    
    return render_template('admin_login.html')

# 관리자 대시보드
@app.route('/admin')
@admin_required
def admin_dashboard():
    """관리자 대시보드"""
    # 전체 통계
    total_users = User.query.count()
    total_students = User.query.filter_by(role=UserRole.STUDENT).count()
    total_professors = User.query.filter_by(role=UserRole.PROFESSOR).count()
    total_admins = User.query.filter_by(role=UserRole.ADMIN).count()
    
    # 상담 통계
    total_counselings = CounselingRecord.query.count()
    pending_counselings = CounselingRecord.query.filter_by(status=CounselingStatus.PENDING).count()
    in_progress_counselings = CounselingRecord.query.filter_by(status=CounselingStatus.IN_PROGRESS).count()
    completed_counselings = CounselingRecord.query.filter_by(status=CounselingStatus.COMPLETED).count()
    
    # 긴급 상담 (레벨 4-5)
    urgent_counselings = CounselingRecord.query.filter(
        CounselingRecord.urgency_level >= 4
    ).order_by(CounselingRecord.urgency_level.desc(), CounselingRecord.created_date.desc()).limit(10).all()
    
    # 최근 등록된 사용자
    recent_users = User.query.order_by(User.created_date.desc()).limit(10).all()
    
    # 최근 상담 목록
    recent_counselings = CounselingRecord.query.order_by(
        CounselingRecord.created_date.desc()
    ).limit(10).all()
    
    # 분야별 통계
    category_stats = {}
    for category in CounselingCategory:
        count = CounselingRecord.query.filter_by(counseling_category=category).count()
        category_stats[category.value] = count
    
    # 이번 달 통계
    from datetime import datetime
    current_date = datetime.now()
    current_month = current_date.month
    current_year = current_date.year
    this_month_counselings = CounselingRecord.query.filter(
        db.extract('month', CounselingRecord.created_date) == current_month,
        db.extract('year', CounselingRecord.created_date) == current_year
    ).count()
    
    this_month_users = User.query.filter(
        db.extract('month', User.created_date) == current_month,
        db.extract('year', User.created_date) == current_year
    ).count()
    
    return render_template('admin_dashboard.html',
                         current_date=current_date,
                         total_users=total_users,
                         total_students=total_students,
                         total_professors=total_professors,
                         total_admins=total_admins,
                         total_counselings=total_counselings,
                         pending_counselings=pending_counselings,
                         in_progress_counselings=in_progress_counselings,
                         completed_counselings=completed_counselings,
                         urgent_counselings=urgent_counselings,
                         recent_users=recent_users,
                         recent_counselings=recent_counselings,
                         category_stats=category_stats,
                         this_month_counselings=this_month_counselings,
                         this_month_users=this_month_users)

# 관리자 사용자 관리
@app.route('/admin/users')
@admin_required
def admin_users():
    """사용자 관리"""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    # 필터링
    role_filter = request.args.get('role')
    status_filter = request.args.get('status')
    search_query = request.args.get('search', '').strip()
    
    query = User.query
    
    if role_filter:
        if role_filter == 'student':
            query = query.filter_by(role=UserRole.STUDENT)
        elif role_filter == 'professor':
            query = query.filter_by(role=UserRole.PROFESSOR)
        elif role_filter == 'admin':
            query = query.filter_by(role=UserRole.ADMIN)
    
    if status_filter:
        if status_filter == 'active':
            query = query.filter_by(is_active=True)
        elif status_filter == 'inactive':
            query = query.filter_by(is_active=False)
    
    if search_query:
        query = query.filter(
            db.or_(
                User.name.contains(search_query),
                User.student_id.contains(search_query),
                User.email.contains(search_query)
            )
        )
    
    users = query.order_by(User.created_date.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    # 통계 데이터 계산
    total_users = User.query.count()
    student_count = User.query.filter_by(role=UserRole.STUDENT).count()
    professor_count = User.query.filter_by(role=UserRole.PROFESSOR).count()
    admin_count = User.query.filter_by(role=UserRole.ADMIN).count()
    active_users = User.query.filter_by(is_active=True).count()
    
    # 각 사용자별 추가 정보 계산
    for user in users.items:
        if user.role == UserRole.STUDENT:
            # 학생의 상담 통계
            user.total_counselings = CounselingRecord.query.filter_by(student_id=user.student_id).count()
            user.completed_counselings = CounselingRecord.query.filter_by(
                student_id=user.student_id,
                status=CounselingStatus.COMPLETED
            ).count()
            
            # 최근 상담 날짜
            recent_counseling = CounselingRecord.query.filter_by(
                student_id=user.student_id
            ).order_by(CounselingRecord.created_date.desc()).first()
            user.last_activity = recent_counseling.created_date if recent_counseling else None
            
        elif user.role == UserRole.PROFESSOR:
            # 교수의 상담 응답 통계
            user.total_counselings = CounselingRecord.query.filter_by(counselor_id=user.student_id).count()
            user.completed_counselings = CounselingRecord.query.filter_by(
                counselor_id=user.student_id,
                status=CounselingStatus.COMPLETED
            ).count()
            
            # 최근 응답 날짜
            recent_response = CounselingRecord.query.filter(
                CounselingRecord.counselor_id == user.student_id,
                CounselingRecord.response_date.isnot(None)
            ).order_by(CounselingRecord.response_date.desc()).first()
            user.last_activity = recent_response.response_date if recent_response else None
        else:
            # 관리자는 기본값
            user.total_counselings = 0
            user.completed_counselings = 0
            user.last_activity = None
    
    return render_template('admin_users.html',
                         users=users,
                         roles=UserRole,
                         total_users=total_users,
                         student_count=student_count,
                         professor_count=professor_count,
                         admin_count=admin_count,
                         active_users=active_users,
                         current_filters={
                             'role': role_filter,
                             'status': status_filter,
                             'search': search_query
                         })

# 관리자 상담 관리
@app.route('/admin/counselings')
@admin_required
def admin_counselings():
    """전체 상담 관리"""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    # 필터링
    category_filter = request.args.get('category')
    status_filter = request.args.get('status')
    urgency_filter = request.args.get('urgency')
    search_query = request.args.get('search', '').strip()
    
    query = CounselingRecord.query
    
    if category_filter:
        try:
            query = query.filter_by(counseling_category=getattr(CounselingCategory, category_filter))
        except AttributeError:
            pass
    
    if status_filter:
        try:
            query = query.filter_by(status=getattr(CounselingStatus, status_filter))
        except AttributeError:
            pass
    
    if urgency_filter:
        try:
            query = query.filter_by(urgency_level=int(urgency_filter))
        except (ValueError, TypeError):
            pass
    
    if search_query:
        query = query.filter(
            db.or_(
                CounselingRecord.student_name.contains(search_query),
                CounselingRecord.counseling_title.contains(search_query),
                CounselingRecord.counseling_content.contains(search_query)
            )
        )
    
    counselings_pagination = query.order_by(
        CounselingRecord.urgency_level.desc(),
        CounselingRecord.created_date.desc()
    ).paginate(page=page, per_page=per_page, error_out=False)
    
    # 상태별 카운트 계산 (현재 페이지 기준)
    status_counts = {
        'pending': 0,
        'in_progress': 0,
        'completed': 0
    }
    
    for counseling in counselings_pagination.items:
        if counseling.status == CounselingStatus.PENDING:
            status_counts['pending'] += 1
        elif counseling.status == CounselingStatus.IN_PROGRESS:
            status_counts['in_progress'] += 1
        elif counseling.status == CounselingStatus.COMPLETED:
            status_counts['completed'] += 1
    
    return render_template('admin_counselings.html',
                         counselings=counselings_pagination.items,
                         pagination=counselings_pagination,
                         categories=CounselingCategory,
                         statuses=CounselingStatus,
                         status_counts=status_counts,
                         current_filters={
                             'category': category_filter,
                             'status': status_filter,
                             'urgency': urgency_filter,
                             'search': search_query
                         })

# 관리자 상담 상세보기
@app.route('/admin/counseling/<int:counseling_id>', methods=['GET', 'POST'])
@admin_required
def admin_counseling_detail(counseling_id):
    """관리자용 상담 상세보기"""
    counseling = db.session.get(CounselingRecord, counseling_id)
    if not counseling:
        flash('상담 기록을 찾을 수 없습니다.', 'error')
        return redirect(url_for('admin_counselings'))
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'admin_memo':
            # 관리자 메모 저장
            admin_memo = request.form.get('admin_memo', '').strip()
            counseling.admin_memo = admin_memo
            db.session.commit()
            flash('관리자 메모가 저장되었습니다.', 'success')
            
        elif action == 'respond':
            # 관리자 답변 저장
            try:
                response_content = request.form.get('response', '').strip()
                if response_content:
                    counseling.counseling_response = response_content
                    counseling.response_date = datetime.utcnow()
                
                # 상태 업데이트
                status_code = request.form.get('status')
                if status_code:
                    try:
                        counseling.status = getattr(CounselingStatus, status_code)
                    except AttributeError:
                        counseling.status = CounselingStatus.IN_PROGRESS
                
                # 관리자 ID를 상담자로 설정
                current_user = db.session.get(User, session['user_id'])
                counseling.counselor_id = current_user.student_id
                
                # 후속 관리 설정
                counseling.follow_up_needed = 'follow_up' in request.form
                if counseling.follow_up_needed and request.form.get('follow_up_date'):
                    try:
                        follow_up_date_str = request.form['follow_up_date']
                        counseling.follow_up_date = datetime.strptime(follow_up_date_str, '%Y-%m-%d')
                    except ValueError:
                        pass
                
                # 메모 추가
                notes = request.form.get('notes', '').strip()
                if notes:
                    current_time = datetime.now().strftime('%Y-%m-%d %H:%M')
                    if counseling.notes:
                        counseling.notes += f"\n\n[{current_time}] {current_user.name}(관리자): {notes}"
                    else:
                        counseling.notes = f"[{current_time}] {current_user.name}(관리자): {notes}"
                
                counseling.updated_date = datetime.utcnow()
                db.session.commit()
                flash('상담 답변이 성공적으로 저장되었습니다.', 'success')
                
            except Exception as e:
                db.session.rollback()
                flash(f'답변 저장 중 오류가 발생했습니다: {str(e)}', 'error')
                print(f"Error in admin_counseling_detail respond: {str(e)}")
            
        elif action == 'update_status':
            # 상태 및 긴급도 업데이트
            new_status = request.form.get('status')
            new_urgency = request.form.get('urgency_level', type=int)
            
            if new_status:
                try:
                    counseling.status = CounselingStatus[new_status]
                except KeyError:
                    flash('잘못된 상태값입니다.', 'error')
                    
            if new_urgency:
                counseling.urgency_level = new_urgency
                
            counseling.updated_date = datetime.utcnow()
            db.session.commit()
            flash('상담 정보가 업데이트되었습니다.', 'success')
            
        elif action == 'mark_urgent':
            # 긴급 상담으로 표시
            counseling.urgency_level = 5
            counseling.updated_date = datetime.utcnow()
            db.session.commit()
            flash('긴급 상담으로 표시되었습니다.', 'success')
            
        elif action == 'send_followup':
            # 후속 조치 알림 (실제 구현 시 이메일 발송 등)
            counseling.follow_up_needed = True
            counseling.follow_up_date = datetime.utcnow()
            db.session.commit()
            return jsonify({'success': True, 'message': '후속 조치 알림이 설정되었습니다.'})
        
        return redirect(url_for('admin_counseling_detail', counseling_id=counseling_id))
    
    # 학생의 상담 통계
    student_counseling_count = CounselingRecord.query.filter_by(student_id=counseling.student_id).count()
    student_completed_count = CounselingRecord.query.filter_by(
        student_id=counseling.student_id, 
        status=CounselingStatus.COMPLETED
    ).count()
    
    # 사용 가능한 상태 목록
    available_statuses = list(CounselingStatus)
    
    return render_template('admin_counseling_detail.html', 
                         counseling=counseling,
                         student_counseling_count=student_counseling_count,
                         student_completed_count=student_completed_count,
                         available_statuses=available_statuses)

# 관리자 교수 관리 기능 추가
@app.route('/admin/professor-management')
@admin_required
def admin_professor_management():
    """관리자 교수 관리 페이지"""
    professors = User.query.filter_by(role=UserRole.PROFESSOR).order_by(User.created_date.desc()).all()
    
    # 통계 데이터 계산
    total_professors = len(professors)
    active_professors = len([p for p in professors if p.is_active])
    inactive_professors = total_professors - active_professors
    
    # 이번 달 추가된 교수 수
    from datetime import datetime
    current_date = datetime.now()
    current_month = current_date.month
    current_year = current_date.year
    this_month_professors = User.query.filter(
        User.role == UserRole.PROFESSOR,
        db.extract('month', User.created_date) == current_month,
        db.extract('year', User.created_date) == current_year
    ).count()
    
    # 각 교수별 상담 통계 계산
    for professor in professors:
        # 기본값 설정 (안전성 보장)
        professor.total_counselings = 0
        professor.completed_counselings = 0
        professor.pending_counselings = 0
        professor.avg_rating = 0.0
        professor.last_activity = None
        
        try:
            # 상담 통계
            professor.total_counselings = CounselingRecord.query.filter_by(counselor_id=professor.student_id).count()
            professor.completed_counselings = CounselingRecord.query.filter_by(
                counselor_id=professor.student_id,
                status=CounselingStatus.COMPLETED
            ).count()
            professor.pending_counselings = CounselingRecord.query.filter_by(
                counselor_id=professor.student_id,
                status=CounselingStatus.PENDING
            ).count()
            
            # 평균 평점 계산 (satisfaction_score 기반)
            counselings_with_rating = CounselingRecord.query.filter(
                CounselingRecord.counselor_id == professor.student_id,
                CounselingRecord.satisfaction_score.isnot(None)
            ).all()
            
            if counselings_with_rating:
                total_score = sum(c.satisfaction_score for c in counselings_with_rating)
                professor.avg_rating = round(total_score / len(counselings_with_rating), 1)
            else:
                professor.avg_rating = 0.0
        except Exception as e:
            # 오류 발생 시 기본값 유지
            print(f"교수 {professor.name} 통계 계산 오류: {e}")
            pass
        
        # 최근 활동 (최근 상담 응답 날짜)
        recent_counseling = CounselingRecord.query.filter(
            CounselingRecord.counselor_id == professor.student_id,
            CounselingRecord.response_date.isnot(None)
        ).order_by(CounselingRecord.response_date.desc()).first()
        
        professor.last_activity = recent_counseling.response_date if recent_counseling else None
    
    # 필터링 파라미터 (향후 확장을 위해)
    current_filters = {
        'status': request.args.get('status'),
        'search': request.args.get('search', '').strip()
    }
    
    return render_template('admin_professor_management.html', 
                         professors=professors,
                         total_professors=total_professors,
                         active_professors=active_professors,
                         inactive_professors=inactive_professors,
                         this_month_professors=this_month_professors,
                         current_filters=current_filters)

@app.route('/admin/professor/add', methods=['GET', 'POST'])
@admin_required
def admin_add_professor():
    """교수 추가"""
    if request.method == 'POST':
        student_id = request.form.get('student_id', '').strip()
        password = request.form.get('password', '').strip()
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        contact = request.form.get('contact', '').strip()
        
        # 유효성 검사
        if not all([student_id, password, name, email]):
            flash('모든 필수 항목을 입력해주세요.', 'error')
            return render_template('admin_add_professor.html')
        
        # 학번 중복 검사
        if User.query.filter_by(student_id=student_id).first():
            flash('이미 존재하는 학번입니다.', 'error')
            return render_template('admin_add_professor.html')
        
        # 이메일 중복 검사
        if User.query.filter_by(email=email).first():
            flash('이미 존재하는 이메일입니다.', 'error')
            return render_template('admin_add_professor.html')
        
        try:
            # 새 교수 사용자 생성
            professor = User(
                student_id=student_id,
                name=name,
                email=email,
                contact=contact,
                role=UserRole.PROFESSOR,
                is_active=True
            )
            professor.set_password(password)
            
            db.session.add(professor)
            db.session.commit()
            
            flash(f'교수 {name}님이 성공적으로 등록되었습니다.', 'success')
            return redirect(url_for('admin_professor_management'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'교수 등록 중 오류가 발생했습니다: {str(e)}', 'error')
            
    # 통계 데이터 계산 (GET 요청 및 에러 발생 시)
    total_professors = User.query.filter_by(role=UserRole.PROFESSOR).count()
    active_professors = User.query.filter(
        User.role == UserRole.PROFESSOR,
        User.is_active == True
    ).count()
    
    # 이번 달 추가된 교수 수
    from datetime import datetime
    current_date = datetime.now()
    current_month = current_date.month
    current_year = current_date.year
    this_month_professors = User.query.filter(
        User.role == UserRole.PROFESSOR,
        db.extract('month', User.created_date) == current_month,
        db.extract('year', User.created_date) == current_year
    ).count()
    
    # 최근 추가된 교수 목록 (최근 3명)
    recent_professors = User.query.filter_by(role=UserRole.PROFESSOR).order_by(
        User.created_date.desc()
    ).limit(3).all()
    
    return render_template('admin_add_professor.html',
                         total_professors=total_professors,
                         active_professors=active_professors,
                         this_month_professors=this_month_professors,
                         recent_professors=recent_professors)

@app.route('/admin/professor/edit/<int:professor_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_professor(professor_id):
    """교수 수정"""
    professor = User.query.get_or_404(professor_id)
    
    if professor.role != UserRole.PROFESSOR:
        flash('교수 계정만 수정할 수 있습니다.', 'error')
        return redirect(url_for('admin_professor_management'))
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        contact = request.form.get('contact', '').strip()
        is_active = request.form.get('is_active') == 'on'
        new_password = request.form.get('new_password', '').strip()
        
        # 유효성 검사
        if not all([name, email]):
            flash('이름과 이메일은 필수 항목입니다.', 'error')
            return render_template('admin_edit_professor.html', professor=professor)
        
        # 이메일 중복 검사 (본인 제외)
        existing_user = User.query.filter(User.email == email, User.id != professor_id).first()
        if existing_user:
            flash('이미 존재하는 이메일입니다.', 'error')
            return render_template('admin_edit_professor.html', professor=professor)
        
        try:
            # 교수 정보 업데이트
            professor.name = name
            professor.email = email
            professor.contact = contact
            professor.is_active = is_active
            
            # 비밀번호 변경 요청이 있는 경우
            if new_password:
                professor.set_password(new_password)
            
            db.session.commit()
            
            flash(f'교수 {name}님의 정보가 성공적으로 수정되었습니다.', 'success')
            return redirect(url_for('admin_professor_management'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'교수 정보 수정 중 오류가 발생했습니다: {str(e)}', 'error')
            return render_template('admin_edit_professor.html', professor=professor)
    
    # 교수의 상담 통계 계산
    professor.total_counselings = CounselingRecord.query.filter_by(counselor_id=professor.student_id).count()
    professor.completed_counselings = CounselingRecord.query.filter_by(
        counselor_id=professor.student_id,
        status=CounselingStatus.COMPLETED
    ).count()
    professor.pending_counselings = CounselingRecord.query.filter_by(
        counselor_id=professor.student_id,
        status=CounselingStatus.PENDING
    ).count()
    
    # 기본값 설정 및 평균 평점 계산
    try:
        counselings_with_rating = CounselingRecord.query.filter(
            CounselingRecord.counselor_id == professor.student_id,
            CounselingRecord.satisfaction_score.isnot(None)
        ).all()
        
        if counselings_with_rating:
            total_score = sum(c.satisfaction_score for c in counselings_with_rating)
            professor.avg_rating = round(total_score / len(counselings_with_rating), 1)
        else:
            professor.avg_rating = 0.0
    except Exception as e:
        professor.avg_rating = 0.0
        print(f"교수 {professor.name} 평점 계산 오류: {e}")
    
    # 최근 상담 응답 날짜
    recent_counseling = CounselingRecord.query.filter(
        CounselingRecord.counselor_id == professor.student_id,
        CounselingRecord.response_date.isnot(None)
    ).order_by(CounselingRecord.response_date.desc()).first()
    professor.last_activity = recent_counseling.response_date if recent_counseling else None
    
    return render_template('admin_edit_professor.html', professor=professor)

@app.route('/admin/professor/<int:professor_id>/delete', methods=['DELETE'])
@admin_required
def admin_delete_professor(professor_id):
    """교수 비활성화 (삭제)"""
    professor = User.query.get_or_404(professor_id)
    
    if professor.role != UserRole.PROFESSOR:
        return jsonify({'success': False, 'message': '교수 계정만 비활성화할 수 있습니다.'})
    
    try:
        # 완전 삭제 대신 비활성화
        professor.is_active = False
        db.session.commit()
        
        return jsonify({'success': True, 'message': f'교수 {professor.name}님의 계정이 비활성화되었습니다.'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'교수 계정 비활성화 중 오류가 발생했습니다: {str(e)}'})

@app.route('/admin/professor/<int:professor_id>/toggle-status', methods=['POST'])
@admin_required 
def admin_professor_toggle_status(professor_id):
    """교수 활성/비활성 상태 토글"""
    professor = User.query.get_or_404(professor_id)
    
    if professor.role != UserRole.PROFESSOR:
        return jsonify({'success': False, 'message': '교수 계정만 상태를 변경할 수 있습니다.'})
    
    try:
        data = request.get_json()
        is_active = data.get('is_active', not professor.is_active)
        
        professor.is_active = is_active
        db.session.commit()
        
        status = "활성화" if is_active else "비활성화"
        return jsonify({'success': True, 'message': f'교수 {professor.name}님의 계정이 {status}되었습니다.'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'교수 상태 변경 중 오류가 발생했습니다: {str(e)}'})

@app.route('/admin/professors/bulk-action', methods=['POST'])
@admin_required
def admin_professors_bulk_action():
    """교수 일괄 작업"""
    try:
        data = request.get_json()
        action = data.get('action')  # 'activate' or 'deactivate'
        professor_ids = data.get('professor_ids', [])
        
        if not action or not professor_ids:
            return jsonify({'success': False, 'message': '필수 파라미터가 누락되었습니다.'})
        
        professors = User.query.filter(
            User.id.in_(professor_ids),
            User.role == UserRole.PROFESSOR
        ).all()
        
        if not professors:
            return jsonify({'success': False, 'message': '선택된 교수를 찾을 수 없습니다.'})
        
        is_active = action == 'activate'
        for professor in professors:
            professor.is_active = is_active
        
        db.session.commit()
        
        action_text = '활성화' if is_active else '비활성화'
        return jsonify({'success': True, 'message': f'{len(professors)}명의 교수가 {action_text}되었습니다.'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'일괄 작업 중 오류가 발생했습니다: {str(e)}'})



# 사용자 관리 추가 기능들
@app.route('/admin/user/toggle/<int:user_id>', methods=['POST'])
@admin_required
def admin_toggle_user(user_id):
    """사용자 상태 토글 (활성화/비활성화)"""
    user = User.query.get_or_404(user_id)
    
    # 자기 자신은 비활성화할 수 없음
    if user.id == session.get('user_id'):
        if request.is_json:
            return jsonify({'success': False, 'message': '자기 자신의 계정은 비활성화할 수 없습니다.'})
        flash('자기 자신의 계정은 비활성화할 수 없습니다.', 'error')
        return redirect(url_for('admin_users'))
    
    try:
        # JSON 요청 처리
        if request.is_json:
            data = request.get_json()
            user.is_active = data.get('is_active', not user.is_active)
        else:
            # Form 요청 처리 (기존 호환성)
            user.is_active = not user.is_active
        
        db.session.commit()
        
        status_text = "활성화" if user.is_active else "비활성화"
        message = f'{user.name}님의 계정이 {status_text}되었습니다.'
        
        if request.is_json:
            return jsonify({'success': True, 'message': message, 'is_active': user.is_active})
        flash(message, 'success')
        
    except Exception as e:
        db.session.rollback()
        message = f'사용자 상태 변경 중 오류가 발생했습니다: {str(e)}'
        if request.is_json:
            return jsonify({'success': False, 'message': message})
        flash(message, 'error')
    
    return redirect(url_for('admin_users'))

@app.route('/admin/user/delete/<int:user_id>', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    """사용자 비활성화 (삭제)"""
    user = User.query.get_or_404(user_id)
    
    # 자기 자신은 삭제할 수 없음
    if user.id == session.get('user_id'):
        if request.is_json:
            return jsonify({'success': False, 'message': '자기 자신의 계정은 삭제할 수 없습니다.'})
        flash('자기 자신의 계정은 삭제할 수 없습니다.', 'error')
        return redirect(url_for('admin_users'))
    
    try:
        # 완전 삭제 대신 비활성화
        user.is_active = False
        db.session.commit()
        
        if request.is_json:
            return jsonify({'success': True, 'message': f'{user.name}님의 계정이 비활성화되었습니다.'})
        flash(f'{user.name}님의 계정이 비활성화되었습니다.', 'success')
    except Exception as e:
        db.session.rollback()
        if request.is_json:
            return jsonify({'success': False, 'message': f'사용자 계정 비활성화 중 오류가 발생했습니다: {str(e)}'})
        flash(f'사용자 계정 비활성화 중 오류가 발생했습니다: {str(e)}', 'error')
    
    return redirect(url_for('admin_users'))

@app.route('/admin/users/bulk-action', methods=['POST'])
@admin_required
def admin_bulk_user_action():
    """사용자 일괄 작업"""
    # JSON 요청 처리
    if request.is_json:
        data = request.get_json()
        action = data.get('action')
        user_ids = data.get('user_ids', [])
    else:
        # Form 요청 처리 (기존 호환성)
        action = request.form.get('action')
        user_ids = request.form.getlist('user_ids')
    
    if not user_ids:
        if request.is_json:
            return jsonify({'success': False, 'message': '선택된 사용자가 없습니다.'})
        flash('선택된 사용자가 없습니다.', 'error')
        return redirect(url_for('admin_users'))
    
    try:
        users = User.query.filter(User.id.in_(user_ids)).all()
        
        if action == 'activate':
            for user in users:
                user.is_active = True
            db.session.commit()
            message = f'{len(users)}명의 사용자가 활성화되었습니다.'
            if request.is_json:
                return jsonify({'success': True, 'message': message})
            flash(message, 'success')
            
        elif action == 'deactivate':
            # 자기 자신은 제외
            current_user_id = session.get('user_id')
            users = [user for user in users if user.id != current_user_id]
            
            for user in users:
                user.is_active = False
            db.session.commit()
            message = f'{len(users)}명의 사용자가 비활성화되었습니다.'
            if request.is_json:
                return jsonify({'success': True, 'message': message})
            flash(message, 'success')
            
        else:
            message = '잘못된 작업입니다.'
            if request.is_json:
                return jsonify({'success': False, 'message': message})
            flash(message, 'error')
            
    except Exception as e:
        db.session.rollback()
        message = f'일괄 작업 중 오류가 발생했습니다: {str(e)}'
        if request.is_json:
            return jsonify({'success': False, 'message': message})
        flash(message, 'error')
    
    return redirect(url_for('admin_users'))

@app.route('/admin/counseling/<int:counseling_id>/update-notes', methods=['POST'])
@admin_required
def admin_update_counseling_notes(counseling_id):
    """관리자 메모 업데이트"""
    counseling = CounselingRecord.query.get_or_404(counseling_id)
    
    admin_notes = request.form.get('admin_notes', '').strip()
    
    try:
        counseling.admin_memo = admin_notes
        counseling.updated_date = datetime.utcnow()
        db.session.commit()
        
        flash('관리자 메모가 성공적으로 저장되었습니다.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'메모 저장 중 오류가 발생했습니다: {str(e)}', 'error')
    
    return redirect(url_for('admin_counseling_detail', counseling_id=counseling_id))

@app.route('/admin/counseling/<int:counseling_id>/update-status', methods=['POST'])
@admin_required
def admin_update_counseling_status(counseling_id):
    """상담 상태 업데이트"""
    counseling = CounselingRecord.query.get_or_404(counseling_id)
    
    status = request.form.get('status')
    priority = request.form.get('priority')
    assigned_professor = request.form.get('assigned_professor')
    
    try:
        # 상태 업데이트 - 문자열 키를 Enum으로 매핑
        if status:
            status_map = {
                'PENDING': CounselingStatus.PENDING,
                'IN_PROGRESS': CounselingStatus.IN_PROGRESS,
                'COMPLETED': CounselingStatus.COMPLETED,
                'CANCELLED': CounselingStatus.CANCELLED
            }
            if status in status_map:
                counseling.status = status_map[status]
            else:
                flash(f'알 수 없는 상태값입니다: {status}', 'error')
                return redirect(url_for('admin_counseling_detail', counseling_id=counseling_id))
        
        # 우선순위 업데이트 (priority 필드가 없다면 urgency_level 사용)
        if priority:
            priority_map = {
                'LOW': 1,
                'NORMAL': 3,
                'HIGH': 4,
                'URGENT': 5
            }
            counseling.urgency_level = priority_map.get(priority, 3)
        
        # 담당 교수 배정
        if assigned_professor:
            counseling.counselor_id = assigned_professor
        
        counseling.updated_date = datetime.utcnow()
        db.session.commit()
        
        flash('상담 상태가 성공적으로 업데이트되었습니다.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'상태 업데이트 중 오류가 발생했습니다: {str(e)}', 'error')
    
    return redirect(url_for('admin_counseling_detail', counseling_id=counseling_id))

@app.route('/admin/counseling/<int:counseling_id>/export')
@admin_required
def admin_export_counseling(counseling_id):
    """상담 내용 내보내기 (PDF)"""
    counseling = CounselingRecord.query.get_or_404(counseling_id)
    
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
        from reportlab.lib.utils import ImageReader
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
        from io import BytesIO
        import os
        
        # PDF 생성
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)
        story = []
        
        # 한글 폰트 설정 (시스템에 있는 폰트 사용)
        korean_font_registered = False
        try:
            # macOS에서 사용 가능한 한글 폰트들을 순서대로 시도
            font_paths = [
                "/System/Library/Fonts/Supplemental/AppleGothic.ttf",
                "/System/Library/Fonts/Supplemental/NotoSansGothic-Regular.ttf",
                "/System/Library/Fonts/Supplemental/AppleMyungjo.ttf",
                "/System/Library/Fonts/AppleSDGothicNeo.ttc"
            ]
            
            for font_path in font_paths:
                if os.path.exists(font_path):
                    try:
                        pdfmetrics.registerFont(TTFont('Korean', font_path))
                        korean_font_registered = True
                        break
                    except:
                        continue
        except:
            pass
        
        # 한글 폰트가 등록되지 않은 경우 HTML로 폴백
        if not korean_font_registered:
            raise ImportError("한글 폰트를 찾을 수 없습니다. HTML 형태로 내보냅니다.")
        
        styles = getSampleStyleSheet()
        
        # 제목
        title_style = styles['Title']
        title_style.fontName = 'Korean'
        story.append(Paragraph("상담 기록", title_style))
        story.append(Spacer(1, 20))
        
        # 상담 정보
        normal_style = styles['Normal']
        normal_style.fontName = 'Korean'
        
        story.append(Paragraph(f"<b>상담 ID:</b> {counseling.id}", normal_style))
        story.append(Paragraph(f"<b>학생명:</b> {counseling.student_name}", normal_style))
        story.append(Paragraph(f"<b>학번:</b> {counseling.student_id}", normal_style))
        story.append(Paragraph(f"<b>연락처:</b> {counseling.contact or 'N/A'}", normal_style))
        story.append(Paragraph(f"<b>이메일:</b> {counseling.email or 'N/A'}", normal_style))
        story.append(Paragraph(f"<b>상담 분야:</b> {counseling.counseling_category.value}", normal_style))
        story.append(Paragraph(f"<b>상담 제목:</b> {counseling.counseling_title}", normal_style))
        story.append(Paragraph(f"<b>긴급도:</b> {counseling.get_urgency_text()}", normal_style))
        story.append(Paragraph(f"<b>상태:</b> {counseling.status.value}", normal_style))
        story.append(Paragraph(f"<b>담당자:</b> {counseling.counselor_id or '미배정'}", normal_style))
        story.append(Paragraph(f"<b>작성일:</b> {counseling.created_date.strftime('%Y-%m-%d %H:%M')}", normal_style))
        if counseling.response_date:
            story.append(Paragraph(f"<b>응답일:</b> {counseling.response_date.strftime('%Y-%m-%d %H:%M')}", normal_style))
        story.append(Spacer(1, 20))
        
        # 상담 내용
        story.append(Paragraph("<b>상담 내용:</b>", normal_style))
        story.append(Spacer(1, 10))
        story.append(Paragraph(counseling.counseling_content.replace('\n', '<br/>'), normal_style))
        story.append(Spacer(1, 20))
        
        # 교수 응답
        if counseling.professor_response:
            story.append(Paragraph("<b>교수 응답:</b>", normal_style))
            story.append(Spacer(1, 10))
            story.append(Paragraph(counseling.professor_response.replace('\n', '<br/>'), normal_style))
            story.append(Spacer(1, 20))
        
        # 관리자 메모
        if counseling.admin_memo:
            story.append(Paragraph("<b>관리자 메모:</b>", normal_style))
            story.append(Spacer(1, 10))
            story.append(Paragraph(counseling.admin_memo.replace('\n', '<br/>'), normal_style))
        
        # PDF 생성
        doc.build(story)
        buffer.seek(0)
        
        # 파일명 생성
        filename = f"counseling_{counseling.id}_{counseling.student_name}_{counseling.created_date.strftime('%Y%m%d')}.pdf"
        
        return send_file(
            BytesIO(buffer.read()),
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename
        )
        
    except ImportError:
        # reportlab이 설치되어 있지 않은 경우 HTML로 내보내기
        from flask import make_response
        
        html_content = f"""
        <!DOCTYPE html>
        <html lang="ko">
        <head>
            <meta charset="UTF-8">
            <title>상담 기록 - {counseling.student_name}</title>
                         <style>
                 body {{ 
                     font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans KR', 'Malgun Gothic', '맑은 고딕', 'Apple SD Gothic Neo', '애플 SD 고딕 Neo', sans-serif; 
                     margin: 20px; 
                     line-height: 1.6;
                     color: #333;
                 }}
                 .header {{ 
                     border-bottom: 3px solid #003366; 
                     padding-bottom: 15px; 
                     margin-bottom: 30px; 
                     text-align: center;
                 }}
                 .header h1 {{
                     color: #003366;
                     margin: 0;
                     font-size: 24px;
                 }}
                 .section {{ 
                     margin: 25px 0; 
                     page-break-inside: avoid;
                 }}
                 .label {{ 
                     font-weight: bold; 
                     color: #003366; 
                     font-size: 16px;
                     margin-bottom: 8px;
                 }}
                 .content {{ 
                     margin: 10px 0; 
                     padding: 15px; 
                     background-color: #f8f9fa; 
                     border-radius: 8px; 
                     border-left: 4px solid #003366;
                     white-space: pre-wrap;
                     word-wrap: break-word;
                 }}
                 .info-grid {{
                     display: grid;
                     grid-template-columns: 1fr 1fr;
                     gap: 10px;
                 }}
                 .info-item {{
                     padding: 8px;
                     background-color: #ffffff;
                     border-radius: 5px;
                     border: 1px solid #e9ecef;
                 }}
                 @media print {{ 
                     body {{ margin: 10px; font-size: 12px; }} 
                     .header h1 {{ font-size: 20px; }}
                     .section {{ margin: 15px 0; }}
                 }}
             </style>
        </head>
        <body>
            <div class="header">
                <h1>원광대학교 컴퓨터소프트웨어공학과 상담 기록</h1>
            </div>
            
            <div class="section">
                <div class="label">상담 ID:</div>
                <div class="content">{counseling.id}</div>
            </div>
            
                         <div class="section">
                 <div class="label">학생 정보</div>
                 <div class="info-grid">
                     <div class="info-item"><strong>이름:</strong> {counseling.student_name}</div>
                     <div class="info-item"><strong>학번:</strong> {counseling.student_id}</div>
                     <div class="info-item"><strong>연락처:</strong> {counseling.contact or 'N/A'}</div>
                     <div class="info-item"><strong>이메일:</strong> {counseling.email or 'N/A'}</div>
                 </div>
             </div>
             
             <div class="section">
                 <div class="label">상담 정보</div>
                 <div class="info-grid">
                     <div class="info-item"><strong>분야:</strong> {counseling.counseling_category.value}</div>
                     <div class="info-item"><strong>긴급도:</strong> {counseling.get_urgency_text()}</div>
                     <div class="info-item"><strong>상태:</strong> {counseling.status.value}</div>
                     <div class="info-item"><strong>담당자:</strong> {counseling.counselor_id or '미배정'}</div>
                     <div class="info-item"><strong>작성일:</strong> {counseling.created_date.strftime('%Y-%m-%d %H:%M')}</div>
                     {'<div class="info-item"><strong>응답일:</strong> ' + counseling.response_date.strftime('%Y-%m-%d %H:%M') + '</div>' if counseling.response_date else ''}
                 </div>
                 <div class="content" style="margin-top: 15px;">
                     <strong>상담 제목:</strong> {counseling.counseling_title}
                 </div>
             </div>
                         
             <div class="section">
                 <div class="label">상담 내용</div>
                 <div class="content">{counseling.counseling_content.replace(chr(10), '<br>')}</div>
             </div>
             
             {f'''
             <div class="section">
                 <div class="label">교수 응답</div>
                 <div class="content">{counseling.professor_response.replace(chr(10), '<br>')}</div>
             </div>
             ''' if counseling.professor_response else ''}
             
             {f'''
             <div class="section">
                 <div class="label">관리자 메모</div>
                 <div class="content">{counseling.admin_memo.replace(chr(10), '<br>')}</div>
             </div>
             ''' if counseling.admin_memo else ''}
            
            <script>
                window.onload = function() {{
                    window.print();
                }}
            </script>
        </body>
        </html>
        """
        
        response = make_response(html_content)
        response.headers['Content-Type'] = 'text/html; charset=utf-8'
        return response
        
    except Exception as e:
        flash(f'내보내기 중 오류가 발생했습니다: {str(e)}', 'error')
        return redirect(url_for('admin_counseling_detail', counseling_id=counseling_id))

@app.route('/admin/counseling/<int:counseling_id>/status', methods=['POST'])
@admin_required
def admin_update_counseling_status_short(counseling_id):
    """상담 상태 업데이트 (짧은 URL - AJAX용)"""
    # admin_update_counseling_status와 동일한 로직
    return admin_update_counseling_status(counseling_id)

@app.route('/admin/counseling/<int:counseling_id>/assign-to-me', methods=['POST'])
@admin_required
def admin_assign_to_me(counseling_id):
    """상담을 현재 관리자에게 할당"""
    counseling = CounselingRecord.query.get_or_404(counseling_id)
    
    try:
        counseling.counselor_id = session.get('user_id', 'admin')
        counseling.status = CounselingStatus.IN_PROGRESS
        counseling.updated_date = datetime.utcnow()
        db.session.commit()
        
        return jsonify({'success': True, 'message': '상담이 할당되었습니다.'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'할당 중 오류가 발생했습니다: {str(e)}'}), 500

@app.route('/admin/counseling/<int:counseling_id>/mark-urgent', methods=['POST'])
@admin_required
def admin_mark_urgent(counseling_id):
    """상담을 긴급으로 표시"""
    counseling = CounselingRecord.query.get_or_404(counseling_id)
    
    try:
        counseling.urgency_level = 5  # 최고 긴급도
        counseling.updated_date = datetime.utcnow()
        db.session.commit()
        
        return jsonify({'success': True, 'message': '긴급 상담으로 표시되었습니다.'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'처리 중 오류가 발생했습니다: {str(e)}'}), 500

@app.route('/admin/counseling/<int:counseling_id>/send-notification', methods=['POST'])
@admin_required
def admin_send_notification(counseling_id):
    """관련자에게 알림 발송"""
    counseling = CounselingRecord.query.get_or_404(counseling_id)
    
    try:
        # 실제 알림 발송 로직은 추후 구현
        # 현재는 성공 응답만 반환
        return jsonify({'success': True, 'message': '알림이 발송되었습니다.'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'알림 발송 중 오류가 발생했습니다: {str(e)}'}), 500

@app.route('/admin/counseling/<int:counseling_id>/cancel', methods=['POST'])
@admin_required
def admin_cancel_counseling(counseling_id):
    """상담 취소"""
    counseling = CounselingRecord.query.get_or_404(counseling_id)
    
    try:
        data = request.get_json()
        reason = data.get('reason', '').strip()
        
        if not reason:
            return jsonify({'success': False, 'message': '취소 사유를 입력해주세요.'}), 400
        
        counseling.status = CounselingStatus.CANCELLED
        counseling.admin_memo = f"{counseling.admin_memo or ''}\n\n[취소] {reason}".strip()
        counseling.updated_date = datetime.utcnow()
        db.session.commit()
        
        return jsonify({'success': True, 'message': '상담이 취소되었습니다.'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'취소 처리 중 오류가 발생했습니다: {str(e)}'}), 500

@app.route('/admin/counseling/<int:counseling_id>/report')
@admin_required
def admin_counseling_report(counseling_id):
    """상담 보고서 생성"""
    counseling = CounselingRecord.query.get_or_404(counseling_id)
    
    # 보고서 HTML 생성
    report_html = f"""
    <!DOCTYPE html>
    <html lang="ko">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>상담 보고서 - {counseling.student_name}</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 30px; line-height: 1.6; }}
            .header {{ border-bottom: 3px solid #0066cc; padding-bottom: 20px; margin-bottom: 30px; }}
            .title {{ color: #0066cc; font-size: 28px; font-weight: bold; margin: 0; }}
            .subtitle {{ color: #666; font-size: 16px; margin-top: 5px; }}
            .section {{ margin: 25px 0; padding: 20px; border-left: 4px solid #0066cc; background: #f8f9fa; }}
            .label {{ font-weight: bold; color: #0066cc; margin-bottom: 8px; }}
            .content {{ margin-bottom: 15px; }}
            .status {{ padding: 5px 15px; border-radius: 20px; font-weight: bold; display: inline-block; }}
            .status-pending {{ background: #fff3cd; color: #856404; }}
            .status-progress {{ background: #cce5ff; color: #004085; }}
            .status-completed {{ background: #d4edda; color: #155724; }}
            .status-cancelled {{ background: #f8d7da; color: #721c24; }}
            @media print {{ body {{ margin: 0; }} }}
        </style>
    </head>
    <body>
        <div class="header">
            <div class="title">상담 보고서</div>
            <div class="subtitle">생성일: {datetime.now().strftime('%Y년 %m월 %d일 %H:%M')}</div>
        </div>
        
        <div class="section">
            <div class="label">기본 정보</div>
            <div class="content"><strong>상담 ID:</strong> {counseling.id}</div>
            <div class="content"><strong>학생명:</strong> {counseling.student_name}</div>
            <div class="content"><strong>학번:</strong> {counseling.student_id}</div>
            <div class="content"><strong>상담 분야:</strong> {counseling.counseling_category.value}</div>
            <div class="content"><strong>상담 제목:</strong> {counseling.counseling_title}</div>
            <div class="content"><strong>상태:</strong> 
                <span class="status status-{counseling.status.name.lower()}">{counseling.status.value}</span>
            </div>
        </div>
        
        <div class="section">
            <div class="label">상담 내용</div>
            <div class="content">{counseling.counseling_content.replace(chr(10), '<br>')}</div>
        </div>
        
        {'<div class="section"><div class="label">교수 응답</div><div class="content">' + counseling.professor_response.replace(chr(10), '<br>') + '</div></div>' if counseling.professor_response else ''}
        
        {'<div class="section"><div class="label">관리자 메모</div><div class="content">' + counseling.admin_memo.replace(chr(10), '<br>') + '</div></div>' if counseling.admin_memo else ''}
        
        <div class="section">
            <div class="label">처리 정보</div>
            <div class="content"><strong>작성일:</strong> {counseling.created_date.strftime('%Y-%m-%d %H:%M') if counseling.created_date else 'N/A'}</div>
            <div class="content"><strong>응답일:</strong> {counseling.response_date.strftime('%Y-%m-%d %H:%M') if counseling.response_date else 'N/A'}</div>
            <div class="content"><strong>담당자:</strong> {counseling.counselor_id or 'N/A'}</div>
            <div class="content"><strong>긴급도:</strong> {counseling.get_urgency_text()}</div>
        </div>
    </body>
    </html>
    """
    
    return report_html

# 교수용 상담 상태 업데이트 엔드포인트 추가
@app.route('/professor/counseling/<int:counseling_id>/status', methods=['POST'])
@professor_required
def professor_update_counseling_status(counseling_id):
    """교수용 상담 상태 업데이트"""
    counseling = CounselingRecord.query.get_or_404(counseling_id)
    
    try:
        data = request.get_json()
        status = data.get('status')
        
        # 상태 매핑
        status_mapping = {
            'PENDING': CounselingStatus.PENDING,
            'IN_PROGRESS': CounselingStatus.IN_PROGRESS,
            'COMPLETED': CounselingStatus.COMPLETED,
            'CANCELLED': CounselingStatus.CANCELLED
        }
        
        if status in status_mapping:
            counseling.status = status_mapping[status]
            counseling.updated_date = datetime.utcnow()
            db.session.commit()
            
            return jsonify({
                'success': True, 
                'message': '상태가 업데이트되었습니다.',
                'new_status': counseling.status.value
            })
        else:
            return jsonify({'success': False, 'message': '잘못된 상태입니다.'}), 400
            
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'업데이트 중 오류가 발생했습니다: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5001)