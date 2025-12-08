
from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from . import db, login_manager

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
    access_level = db.Column(db.String(20), default='basic')  # basic, text_only, full_access
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
                              primaryjoin="User.id==UserCourse.user_id",
                              secondaryjoin="Course.id==UserCourse.course_id",
                              backref='enrolled_users')
    lesson_progress = db.relationship('UserLessonProgress',
                                   backref='user',
                                   lazy='dynamic',
                                   cascade='all, delete-orphan')
    
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
            self.access_level = access_info['access_level']
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
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    interest_id = db.Column(db.Integer, db.ForeignKey('interests.id'), primary_key=True)
    access_granted = db.Column(db.Boolean, default=False)
    granted_at = db.Column(db.DateTime)
    granted_by = db.Column(db.Integer, db.ForeignKey('users.id'))


class Course(db.Model):
    __tablename__ = 'courses'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    cover_image_url = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    # Relationships
    lessons = db.relationship('Lesson', backref='course', lazy='dynamic', cascade='all, delete-orphan')
    forum_topics = db.relationship('ForumTopic', backref='course', lazy='dynamic')
    
    def is_thbs_restricted(self):
        """Check if this course is restricted to THBS domain users only"""
        # Check if the course title contains "erlang-l3" (case-insensitive)
        return 'erlang-l3' in self.title.lower()
    
    def user_can_access_course(self, user):
        """Check if a user can access this course based on domain restrictions"""
        if not user.is_authenticated or not user.is_approved:
            return False
            
        # Admins can access everything
        if user.is_admin:
            return True
            
        # Check if this is a THBS-restricted course
        if self.is_thbs_restricted():
            # Only THBS domain users can access erlang-l3 courses
            return user.email_domain == 'thbs.com'
            
        # For non-restricted courses, check regular interest-based access
        return True  # Will be checked by existing interest-based logic
    
    def __repr__(self):
        return f'<Course {self.title}>'


class CourseInterest(db.Model):
    __tablename__ = 'course_interest'
    course_id = db.Column(db.Integer, db.ForeignKey('courses.id'), primary_key=True)
    interest_id = db.Column(db.Integer, db.ForeignKey('interests.id'), primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))


class UserCourse(db.Model):
    __tablename__ = 'user_course'
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    course_id = db.Column(db.Integer, db.ForeignKey('courses.id'), primary_key=True)
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
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
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
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('courses.id'))  # Null means general forum
    pinned = db.Column(db.Boolean, default=False)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('forum_topics', lazy='dynamic'))
    replies = db.relationship('ForumReply', backref='topic', lazy='dynamic', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<ForumTopic {self.title}>'


class ForumReply(db.Model):
    __tablename__ = 'forum_replies'
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    topic_id = db.Column(db.Integer, db.ForeignKey('forum_topics.id'), nullable=False)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('forum_replies', lazy='dynamic'))
    
    def __repr__(self):
        return f'<ForumReply {self.id} by user {self.user_id}>'


class UserNote(db.Model):
    """User notes for lessons - interactive learning feature"""
    __tablename__ = 'user_notes'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
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
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
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
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    activity_type = db.Column(db.String(50), nullable=False)  # lesson_started, lesson_completed, note_added, etc.
    activity_data = db.Column(db.Text)  # JSON data for the activity
    lesson_id = db.Column(db.Integer, db.ForeignKey('lessons.id'))
    course_id = db.Column(db.Integer, db.ForeignKey('courses.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('activities', lazy='dynamic'))
    lesson = db.relationship('Lesson', backref=db.backref('activities', lazy='dynamic'))
    course = db.relationship('Course', backref=db.backref('activities', lazy='dynamic'))
    
    def __repr__(self):
        return f'<UserActivity {self.activity_type} by user {self.user_id}>'
