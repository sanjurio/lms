from sqlalchemy import event
from sqlalchemy.engine import Engine
import sqlite3
from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from . import db, login_manager

@event.listens_for(Engine, "connect")
def enable_sqlite_fk(dbapi_connection, connection_record):
    if isinstance(dbapi_connection, sqlite3.Connection):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.close()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_approved = db.Column(db.Boolean, default=False)
    otp_secret = db.Column(db.String(32))
    is_2fa_enabled = db.Column(db.Boolean, default=False)
    access_level = db.Column(db.Integer, default=1)  # 1=D1, 2=D2, 3=D3, 4=D4
    email_domain = db.Column(db.String(50))  # Store email domain for quick access
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    interests = db.relationship('Interest', 
                              secondary='user_interest',
                              primaryjoin="User.id==UserInterest.user_id",
                              secondaryjoin="Interest.id==UserInterest.interest_id",
                              backref='users')
    courses = db.relationship('Course', 
                              secondary='user_course',
                              passive_deletes=True,
                              primaryjoin="User.id==UserCourse.user_id",
                              secondaryjoin="Course.id==UserCourse.course_id",
                              backref='enrolled_users')
    lesson_progress = db.relationship('UserLessonProgress',
                                   backref='user',
                                   lazy='dynamic',
                                   cascade='all, delete-orphan',
                                   passive_deletes=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def set_access_based_on_domain(self):
        """Set user access level based on email domain"""
        from .utils.auth_helpers import get_domain_access_info
        if self.email:
            domain = self.email.split('@')[-1].lower()
            self.email_domain = domain
            
            access_info = get_domain_access_info(self.email)
            self.access_level = access_info.get('access_level', 'basic')
            self.is_approved = False  # Always require admin approval
    
    def can_view_videos(self):
        """Check if user can view video content (Erlang system demonstrations)"""
        return self.access_level == 'full_access'
    
    def can_view_text(self):
        """Check if user can view text content (Erlang documentation and tutorials)"""
        return self.access_level in ['text_only', 'full_access']
    
    def get_progress_stats(self):
        """Get user's learning progress statistics"""
        # Get user's approved interests
        user_interests = UserInterest.query.filter_by(
            user_id=self.id,
            access_granted=True
        ).all()
        
        if not user_interests:
            return {
                'total_lessons': 0,
                'completed_lessons': 0,
                'in_progress_lessons': 0,
                'completion_percentage': 0
            }
        
        # Get interest IDs
        interest_ids = [ui.interest_id for ui in user_interests]
        
        # Get courses for these interests
        course_interests = CourseInterest.query.filter(
            CourseInterest.interest_id.in_(interest_ids)
        ).all()
        
        if not course_interests:
            total_lessons = 0
        else:
            course_ids = [ci.course_id for ci in course_interests]
            total_lessons = Lesson.query.filter(
                Lesson.course_id.in_(course_ids)
            ).count()
        
        completed_lessons = self.lesson_progress.filter(
            UserLessonProgress.status == 'completed'
        ).count()
        
        in_progress_lessons = self.lesson_progress.filter(
            UserLessonProgress.status == 'in_progress'
        ).count()
        
        return {
            'total_lessons': total_lessons,
            'completed_lessons': completed_lessons,
            'in_progress_lessons': in_progress_lessons,
            'completion_percentage': (completed_lessons / total_lessons * 100) if total_lessons > 0 else 0
        }
    
    def get_recent_activity(self, limit=5):
        """Get user's recent activities"""
        return self.activities.order_by(UserActivity.created_at.desc()).limit(limit).all()
    
    def get_bookmarked_lessons(self):
        """Get user's bookmarked lessons"""
        return db.session.query(Lesson).join(UserBookmark).filter(
            UserBookmark.user_id == self.id
        ).all()
    
    def get_current_lesson(self):
        """Get the lesson user is currently working on"""
        progress = self.lesson_progress.filter(
            UserLessonProgress.status == 'in_progress'
        ).order_by(UserLessonProgress.last_interaction.desc()).first()
        
        return progress.lesson if progress else None
    
    def __repr__(self):
        return f'<User {self.username}>'


class Interest(db.Model):
    __tablename__ = 'interests'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Interest {self.name}>'
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    # Relationships
    courses = db.relationship('Course', 
                           secondary='course_interest',
                           primaryjoin="Interest.id==CourseInterest.interest_id",
                           secondaryjoin="Course.id==CourseInterest.course_id",
                           backref='interests')
    
    def __repr__(self):
        return f'<Interest {self.name}>'


class UserInterest(db.Model):
    __tablename__ = 'user_interest'
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), primary_key=True)
    interest_id = db.Column(db.Integer, db.ForeignKey('interests.id', ondelete='CASCADE'), primary_key=True)
    access_granted = db.Column(db.Boolean, default=False)
    granted_at = db.Column(db.DateTime)
    granted_by = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)


class Course(db.Model):
    __tablename__ = 'courses'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    cover_image_url = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    issue_certificates = db.Column(db.Boolean, default=False)
    required_level = db.Column(db.Integer, default=1)  # 1=D1, 2=D2, 3=D3, 4=D4
    
    # Relationships with proper cascade delete
    lessons = db.relationship('Lesson', backref='course', lazy='dynamic', cascade='all, delete-orphan')
    forum_topics = db.relationship('ForumTopic', backref='course', lazy='dynamic', cascade='all, delete-orphan')
    assignments = db.relationship('Assignment', backref='course', lazy='dynamic', cascade='all, delete-orphan')
    
    def is_thbs_restricted(self):
        """Check if this course is restricted to THBS domain users only"""
        # Check if the course title contains "-thbs" (case-insensitive)
        return '-thbs' in self.title.lower()
    
    def user_can_access_course(self, user):
        """Check if a user can access this course based on level and domain restrictions"""
        if not user.is_authenticated or not user.is_approved:
            return False
            
        # Admins can access everything
        if user.is_admin:
            return True
            
        # Hierarchical level check: user level must be >= course required level
        if (user.access_level or 1) < (self.required_level or 1):
            return False

        # Check if this is a THBS-restricted course
        if self.is_thbs_restricted():
            # Only THBS domain users can access -thbs courses
            return user.email_domain == 'thbs.com'
            
        # For non-restricted courses, check regular interest-based logic
        return True
    
    def __repr__(self):
        return f'<Course {self.title}>'


class CourseInterest(db.Model):
    __tablename__ = 'course_interest'
    course_id = db.Column(db.Integer, db.ForeignKey('courses.id', ondelete='CASCADE'), primary_key=True)
    interest_id = db.Column(db.Integer, db.ForeignKey('interests.id', ondelete='CASCADE'), primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)


class UserCourse(db.Model):
    __tablename__ = 'user_course'
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), primary_key=True)
    course_id = db.Column(db.Integer, db.ForeignKey('courses.id', ondelete='CASCADE'), primary_key=True)
    enrollment_date = db.Column(db.DateTime, default=datetime.utcnow)
    completed = db.Column(db.Boolean, default=False)
    
    def __repr__(self):
        return f'<UserCourse user_id={self.user_id} course_id={self.course_id}>'


class Lesson(db.Model):
    __tablename__ = 'lessons'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    content_type = db.Column(db.String(20), default='text')  # text, video, mixed
    video_url = db.Column(db.String(500))  # For video content
    course_id = db.Column(db.Integer, db.ForeignKey('courses.id'), nullable=False)
    order = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship with user progress
    user_progress = db.relationship('UserLessonProgress', backref='lesson', lazy='dynamic', cascade='all, delete-orphan')
    
    def can_view_content(self, user):
        """Check if user can view this lesson's content based on their access level"""
        if not user.is_authenticated:
            return False
            
        if self.content_type == 'text':
            return user.can_view_text()
        elif self.content_type == 'video':
            return user.can_view_videos()
        elif self.content_type == 'mixed':
            # For mixed content, return what parts they can see
            return {
                'text': user.can_view_text(),
                'video': user.can_view_videos()
            }
        return False
    
    def __repr__(self):
        return f'<Lesson {self.title}>'


class UserLessonProgress(db.Model):
    __tablename__ = 'user_lesson_progress'
    user_id = db.Column(db.Integer, db.ForeignKey('users.id',ondelete='CASCADE'), primary_key=True)
    lesson_id = db.Column(db.Integer, db.ForeignKey('lessons.id'), primary_key=True)
    status = db.Column(db.String(20), default='not_started')  # not_started, in_progress, completed
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    last_interaction = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<UserLessonProgress user_id={self.user_id} lesson_id={self.lesson_id} status={self.status}>'


class ForumTopic(db.Model):
    __tablename__ = 'forum_topics'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('courses.id'))  # Null means general forum
    pinned = db.Column(db.Boolean, default=False)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('forum_topics', lazy='dynamic' , cascade='all, delete-orphan'))
    replies = db.relationship('ForumReply', backref='topic', lazy='dynamic', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<ForumTopic {self.title}>'


class ForumReply(db.Model):
    __tablename__ = 'forum_replies'
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    topic_id = db.Column(db.Integer, db.ForeignKey('forum_topics.id', ondelete='CASCADE'), nullable=False)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('forum_replies', lazy='dynamic' , cascade='all, delete-orphan'))
    
    def __repr__(self):
        return f'<ForumReply {self.id} by user {self.user_id}>'


class UserNote(db.Model):
    """User notes for lessons - interactive learning feature"""
    __tablename__ = 'user_notes'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    lesson_id = db.Column(db.Integer, db.ForeignKey('lessons.id'), nullable=False)
    note_text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('notes', lazy='dynamic'))
    lesson = db.relationship('Lesson', backref=db.backref('notes', lazy='dynamic'))
    
    def __repr__(self):
        return f'<UserNote {self.id} by user {self.user_id}>'


class UserBookmark(db.Model):
    """User bookmarks for lessons - interactive learning feature"""
    __tablename__ = 'user_bookmarks'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    lesson_id = db.Column(db.Integer, db.ForeignKey('lessons.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('bookmarks', lazy='dynamic'))
    lesson = db.relationship('Lesson', backref=db.backref('bookmarks', lazy='dynamic'))
    
    def __repr__(self):
        return f'<UserBookmark {self.id} by user {self.user_id}>'


class UserActivity(db.Model):
    """Track user activities for enhanced dashboard"""
    __tablename__ = 'user_activities'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id',ondelete='CASCADE'), nullable=False)
    activity_type = db.Column(db.String(50), nullable=False)  # lesson_started, lesson_completed, note_added, etc.
    activity_data = db.Column(db.Text)  # JSON data for the activity
    lesson_id = db.Column(db.Integer, db.ForeignKey('lessons.id'))
    course_id = db.Column(db.Integer, db.ForeignKey('courses.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('activities', lazy='dynamic' , passive_deletes=True))
    lesson = db.relationship('Lesson', backref=db.backref('activities', lazy='dynamic'))
    course = db.relationship('Course', backref=db.backref('activities', lazy='dynamic'))
    
    def __repr__(self):
        return f'<UserActivity {self.activity_type} by user {self.user_id}>'


class MandatoryCourse(db.Model):
    """Track mandatory course assignments - for all users or specific users"""
    __tablename__ = 'mandatory_courses'
    id = db.Column(db.Integer, primary_key=True)
    course_id = db.Column(db.Integer, db.ForeignKey('courses.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=True)  # NULL means mandatory for all users
    deadline = db.Column(db.DateTime, nullable=True)  # Optional deadline (default 1 month from assignment)
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)
    assigned_by = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    requires_redo = db.Column(db.Boolean, default=False)  # If True, user must redo the course even if completed
    
    # Relationships
    course = db.relationship('Course', backref=db.backref('mandatory_assignments', lazy='dynamic'), foreign_keys=[course_id])
    user = db.relationship('User', backref=db.backref('mandatory_courses', lazy='dynamic', cascade='all, delete-orphan', passive_deletes=True), foreign_keys=[user_id])
    assigner = db.relationship('User', foreign_keys=[assigned_by], passive_deletes=True)
    
    def __repr__(self):
        if self.user_id:
            return f'<MandatoryCourse course_id={self.course_id} user_id={self.user_id}>'
        return f'<MandatoryCourse course_id={self.course_id} for_all_users=True>'
    
    @staticmethod
    def is_mandatory_for_user(course_id, user_id):
        """Check if a course is mandatory for a specific user"""
        # Check if mandatory for all users
        global_mandatory = MandatoryCourse.query.filter_by(course_id=course_id, user_id=None).first()
        if global_mandatory:
            return True
        # Check if mandatory for this specific user
        user_mandatory = MandatoryCourse.query.filter_by(course_id=course_id, user_id=user_id).first()
        return user_mandatory is not None
    
    @staticmethod
    def get_user_mandatory_courses(user_id):
        """Get all mandatory courses for a user (both global and user-specific)"""
        from sqlalchemy import or_
        return MandatoryCourse.query.filter(
            or_(MandatoryCourse.user_id == None, MandatoryCourse.user_id == user_id)
        ).all()
    
    @staticmethod
    def get_deadline_for_user(course_id, user_id):
        """Get the deadline for a mandatory course for a specific user"""
        # First check user-specific assignment
        user_mandatory = MandatoryCourse.query.filter_by(course_id=course_id, user_id=user_id).first()
        if user_mandatory:
            return user_mandatory.deadline
        # Then check global assignment
        global_mandatory = MandatoryCourse.query.filter_by(course_id=course_id, user_id=None).first()
        if global_mandatory:
            return global_mandatory.deadline
        return None


class Assignment(db.Model):
    """Course assignments with MCQ questions"""
    __tablename__ = 'assignments'
    id = db.Column(db.Integer, primary_key=True)
    course_id = db.Column(db.Integer, db.ForeignKey('courses.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    passing_score = db.Column(db.Integer, default=70)  # Percentage required to pass
    time_limit_minutes = db.Column(db.Integer, nullable=True)  # Optional time limit
    max_attempts = db.Column(db.Integer, default=0)  # 0 means unlimited attempts
    shuffle_questions = db.Column(db.Boolean, default=False)
    shuffle_options = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Relationships
    creator = db.relationship('User', foreign_keys=[created_by])
    questions = db.relationship('Question', backref='assignment', lazy='dynamic', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Assignment {self.title}>'
    
    def get_user_attempts(self, user_id):
        """Get all attempts for a specific user"""
        return UserAssignmentAttempt.query.filter_by(
            assignment_id=self.id,
            user_id=user_id
        ).order_by(UserAssignmentAttempt.started_at.desc()).all()
    
    def get_best_score(self, user_id):
        """Get the best score for a user"""
        attempts = self.get_user_attempts(user_id)
        if not attempts:
            return None
        completed = [a for a in attempts if a.completed_at]
        if not completed:
            return None
        return max(a.score for a in completed)
    
    def user_has_passed(self, user_id):
        """Check if user has passed this assignment"""
        best_score = self.get_best_score(user_id)
        if best_score is None:
            return False
        return best_score >= self.passing_score


class Question(db.Model):
    """MCQ questions for assignments"""
    __tablename__ = 'questions'
    id = db.Column(db.Integer, primary_key=True)
    assignment_id = db.Column(db.Integer, db.ForeignKey('assignments.id'), nullable=False)
    question_text = db.Column(db.Text, nullable=False)
    option_a = db.Column(db.String(500), nullable=False)
    option_b = db.Column(db.String(500), nullable=False)
    option_c = db.Column(db.String(500), nullable=True)
    option_d = db.Column(db.String(500), nullable=True)
    correct_answer = db.Column(db.String(1), nullable=False)  # 'A', 'B', 'C', or 'D'
    explanation = db.Column(db.Text)  # Optional explanation for the correct answer
    points = db.Column(db.Integer, default=1)
    order = db.Column(db.Integer, default=0)
    
    def __repr__(self):
        return f'<Question {self.id} for Assignment {self.assignment_id}>'
    
    def get_options(self):
        """Get all options as a list"""
        options = [
            ('A', self.option_a),
            ('B', self.option_b),
        ]
        if self.option_c:
            options.append(('C', self.option_c))
        if self.option_d:
            options.append(('D', self.option_d))
        return options
    
    def is_correct(self, answer):
        """Check if the given answer is correct"""
        return answer.upper() == self.correct_answer.upper()


class UserAssignmentAttempt(db.Model):
    """Track user attempts on assignments"""
    __tablename__ = 'user_assignment_attempts'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    assignment_id = db.Column(db.Integer, db.ForeignKey('assignments.id', ondelete='CASCADE'), nullable=False)
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)
    score = db.Column(db.Integer, default=0)  # Percentage score
    answers = db.Column(db.Text)  # JSON string of answers: {"question_id": "answer"}
    
    # Relationships
    user = db.relationship('User', backref=db.backref('assignment_attempts', lazy='dynamic' , passive_deletes=True))
    assignment = db.relationship('Assignment', backref=db.backref('attempts', lazy='dynamic', cascade='all, delete-orphan', passive_deletes=True))
    
    def __repr__(self):
        return f'<UserAssignmentAttempt user={self.user_id} assignment={self.assignment_id}>'
    
    def is_passed(self):
        """Check if this attempt passed"""
        return self.score >= self.assignment.passing_score if self.completed_at else False


class PasswordResetToken(db.Model):
    """Store password reset OTP tokens"""
    __tablename__ = 'password_reset_tokens'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    otp_code = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    
    # Relationship
    user = db.relationship('User', backref=db.backref('reset_tokens', lazy='dynamic', cascade='all, delete-orphan', passive_deletes=True))
    
    def __repr__(self):
        return f'<PasswordResetToken user_id={self.user_id}>'
    
    def is_valid(self):
        """Check if the token is still valid"""
        return not self.used and datetime.utcnow() < self.expires_at
    
    @staticmethod
    def generate_otp():
        """Generate a 6-digit OTP"""
        import random
        return ''.join([str(random.randint(0, 9)) for _ in range(6)])


class LessonMedia(db.Model):
    """Store multiple media items (videos, files, links) for lessons"""
    __tablename__ = 'lesson_media'
    id = db.Column(db.Integer, primary_key=True)
    lesson_id = db.Column(db.Integer, db.ForeignKey('lessons.id', ondelete='CASCADE'), nullable=False)
    media_type = db.Column(db.String(20), nullable=False)  # youtube, file, link
    title = db.Column(db.String(200))
    url = db.Column(db.String(1000))  # For YouTube URLs and external links
    file_path = db.Column(db.String(500))  # For uploaded files
    file_name = db.Column(db.String(255))  # Original file name
    file_size = db.Column(db.Integer)  # File size in bytes
    order = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    lesson = db.relationship('Lesson', backref=db.backref('media_items', lazy='dynamic', cascade='all, delete-orphan'))
    
    def __repr__(self):
        return f'<LessonMedia {self.media_type} for lesson {self.lesson_id}>'
    
    def get_youtube_embed_url(self):
        """Convert YouTube URL to embed URL"""
        if self.media_type != 'youtube' or not self.url:
            return None
        
        url = self.url.strip()
        video_id = None
        
        if 'youtu.be/' in url:
            video_id = url.split('youtu.be/')[-1].split('?')[0]
        elif 'youtube.com/watch' in url:
            import re
            match = re.search(r'v=([^&]+)', url)
            if match:
                video_id = match.group(1)
        elif 'youtube.com/embed/' in url:
            video_id = url.split('embed/')[-1].split('?')[0]
        
        if video_id:
            return f'https://www.youtube.com/embed/{video_id}'
        return url
    
    def get_file_size_display(self):
        """Return human-readable file size"""
        if not self.file_size:
            return 'Unknown'
        
        size = self.file_size
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f'{size:.1f} {unit}'
            size /= 1024
        return f'{size:.1f} TB'


class EmailVerificationToken(db.Model):
    """Store email verification OTP tokens for registration"""
    __tablename__ = 'email_verification_tokens'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False, index=True)
    username = db.Column(db.String(64), nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    otp_code = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    verified = db.Column(db.Boolean, default=False)
    
    def __repr__(self):
        return f'<EmailVerificationToken email={self.email}>'
    
    def is_valid(self):
        """Check if the token is still valid"""
        return not self.verified and datetime.utcnow() < self.expires_at
    
    @staticmethod
    def generate_otp():
        """Generate a 6-digit OTP"""
        import random
        return ''.join([str(random.randint(0, 9)) for _ in range(6)])


class MandatoryCourseReminder(db.Model):
    """Track reminder emails sent for mandatory courses"""
    __tablename__ = 'mandatory_course_reminders'
    id = db.Column(db.Integer, primary_key=True)
    mandatory_course_id = db.Column(db.Integer, db.ForeignKey('mandatory_courses.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    reminder_type = db.Column(db.String(20), nullable=False)
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    mandatory_course = db.relationship('MandatoryCourse', backref=db.backref('reminders', lazy='dynamic'))
    user = db.relationship('User', backref=db.backref('course_reminders', lazy='dynamic'))
