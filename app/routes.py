from flask import render_template, flash, redirect, url_for, request, abort, session, jsonify
from flask_login import login_user, logout_user, current_user, login_required
from urllib.parse import urlparse
import os
import io
import json
from . import db
from .models import (User, Course, Lesson, Interest, UserInterest,
                    CourseInterest, UserCourse, ForumTopic, ForumReply,
                    UserLessonProgress, UserNote, UserBookmark, UserActivity,
                    MandatoryCourse, Assignment, Question, UserAssignmentAttempt,
                    PasswordResetToken, LessonMedia, EmailVerificationToken,
                    MandatoryCourseReminder)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash
from .forms import (LoginForm, RegistrationForm, TwoFactorForm,
                   SetupTwoFactorForm, InterestSelectionForm, UserApprovalForm,
                   CourseForm, LessonForm, InterestForm,
                   UserInterestAccessForm, ProfileForm, ForumTopicForm,
                   ForumReplyForm, MandatoryCourseForm, AssignmentForm, QuestionForm,
                   ForgotPasswordForm, VerifyOTPForm, ResetPasswordForm, EmailVerificationForm)
from datetime import timedelta
from .utils.auth_helpers import generate_otp_secret, verify_totp, generate_qr_code
from .utils.course_helpers import get_user_accessible_courses, get_recommended_courses, user_can_access_course, get_user_interests_status
from .utils.admin_helpers import get_pending_users, approve_user, reject_user, grant_interest_access, revoke_interest_access, set_user_video_access
from .document_analysis import analyze_document
from datetime import datetime


def register_routes(app):
    """Register all routes with the Flask app"""

    @app.route('/')
    def index():
        if current_user.is_authenticated:
            if current_user.is_admin:
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('user_dashboard'))

        return render_template('index.html', title='Welcome to Erlang Systems LMS')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for('index'))

        if request.args.get('registration_complete'):
            flash('Registration successful! Your account is pending approval from an administrator.', 'success')
            session.pop('user_created', None)

        form = LoginForm()

        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()

            if user is None or not user.check_password(form.password.data):
                flash('Invalid email or password', 'danger')
                return render_template('auth/login.html', title='Sign In', form=form)

            if not user.is_approved:
                flash('Your account is pending approval from an administrator.', 'warning')
                return render_template('auth/login.html', title='Sign In', form=form)

            # Special case for admin: bypass 2FA
            if user.is_admin:
                login_user(user, remember=form.remember_me.data)
                next_page = request.args.get('next')
                if not next_page or urlparse(next_page).netloc != '':
                    next_page = url_for('index')
                flash('Welcome, Administrator!', 'success')
                return redirect(next_page)

            # Check if user has 2FA enabled globally or for this user
            if not user.is_2fa_enabled:
                login_user(user, remember=form.remember_me.data)
                next_page = request.args.get('next')
                if not next_page or urlparse(next_page).netloc != '':
                    next_page = url_for('index')
                flash('Welcome back!', 'success')
                return redirect(next_page)

            # Check if user has 2FA configured
            if not user.otp_secret:
                flash('Your account is missing 2FA configuration. Please contact an administrator.', 'danger')
                return render_template('auth/login.html', title='Sign In', form=form)

            # Store user info in session for 2FA verification
            session['user_id'] = user.id
            session['remember_me'] = form.remember_me.data
            return redirect(url_for('two_factor_auth'))

        return render_template('auth/login.html', title='Sign In', form=form)

    @app.route('/admin/users/pending')
    @login_required
    def admin_pending_users():
        if not current_user.is_admin:
            flash('You do not have permission to access the admin area.', 'danger')
            return redirect(url_for('index'))

        pending_users = get_pending_users()
        form = UserApprovalForm()

        # Get stats for dashboard cards
        stats = {
            'pending_users_count': User.query.filter_by(is_approved=False, is_admin=False).count(),
            'users_count': User.query.filter_by(is_admin=False).count(),
            'courses_count': Course.query.count(),
            'interests_count': Interest.query.count()
        }

        return render_template('admin/approve_users.html',
                               title='Pending Users',
                               pending_users=pending_users,
                               form=form,
                               **stats)

    @app.route('/admin/users/approve', methods=['POST'])
    @login_required
    def admin_approve_user():
        if not current_user.is_admin:
            abort(403)

        user_id = request.form.get('user_id')
        action = request.form.get('action')
        video_access = request.form.get('video_access')

        if user_id and action:
            try:
                user_id = int(user_id)
                if action == 'approve':
                    if approve_user(user_id, current_user.id):
                        # Set video access if specified
                        if video_access is not None:
                            set_user_video_access(user_id, video_access == 'on')
                        flash('User has been approved successfully.', 'success')
                    else:
                        flash('Error approving user. User may not exist.', 'danger')
                elif action == 'reject':
                    if reject_user(user_id):
                        flash('User has been rejected and removed.', 'success')
                    else:
                        flash('Error rejecting user. User may not exist.', 'danger')
                else:
                    flash('Invalid action specified.', 'danger')
            except ValueError:
                flash('Invalid user ID format.', 'danger')
        else:
            flash('Missing required form data. Please try again.', 'danger')

        return redirect(url_for('admin_pending_users'))

    @app.route('/admin/courses')
    @login_required
    def admin_courses():
        if not current_user.is_admin:
            flash('You do not have permission to access the admin area.', 'danger')
            return redirect(url_for('index'))

        courses = Course.query.all()

        # Get stats for dashboard cards
        stats = {
            'pending_users_count': User.query.filter_by(is_approved=False, is_admin=False).count(),
            'users_count': User.query.filter_by(is_admin=False).count(),
            'courses_count': Course.query.count(),
            'interests_count': Interest.query.count()
        }

        return render_template('admin/content.html',
                               title='Manage Courses',
                               courses=courses,
                               **stats)

    @app.route('/admin/dashboard')
    @login_required
    def admin_dashboard():
        if not current_user.is_admin:
            flash('You do not have permission to access the admin area.', 'danger')
            return redirect(url_for('index'))

        # keep keys consistent with other admin routes/templates
        stats = {
            'pending_users_count': User.query.filter_by(is_approved=False, is_admin=False).count(),
            'users_count': User.query.filter_by(is_admin=False).count(),
            'courses_count': Course.query.count(),
            'interests_count': Interest.query.count()
        }

        # pass as individual variables so templates like admin/dashboard.html can use {{ users_count }}
        return render_template('admin/dashboard.html',
                            title='Admin Dashboard',
                            **stats)


    @app.route('/user/dashboard')
    @login_required
    def user_dashboard():
        if not current_user.is_approved:
            flash('Your account is pending approval.', 'warning')
            return redirect(url_for('logout'))

        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))

        # Get user's interests and available courses
        user_interests = get_user_interests_status(current_user.id)

        # Get courses that the user can access
        available_courses = get_user_accessible_courses(current_user)

        # Get user's progress statistics
        progress_stats = current_user.get_progress_stats()

        # Get user's recent activities
        recent_activities = current_user.get_recent_activity()

        # Get user's bookmarked lessons
        bookmarked_lessons = current_user.get_bookmarked_lessons()

        # Get current lesson (in progress)
        current_lesson = current_user.get_current_lesson()

        # Get recommended courses
        recommended_courses = get_recommended_courses(current_user)
        
        # Calculate per-course progress for dashboard
        course_progress_list = []
        for course in available_courses:
            lessons = Lesson.query.filter_by(course_id=course.id).all()
            completed_lessons = 0
            total_lessons = len(lessons)
            for lesson in lessons:
                progress = UserLessonProgress.query.filter_by(
                    user_id=current_user.id,
                    lesson_id=lesson.id
                ).first()
                if progress and progress.status == 'completed':
                    completed_lessons += 1
            
            lessons_percentage = round((completed_lessons / total_lessons * 100) if total_lessons > 0 else 0)
            
            assignments = Assignment.query.filter_by(course_id=course.id, is_active=True).all()
            assignment_passed = False
            assignment_required = len(assignments) > 0
            assignment_info = None
            
            if assignments:
                for assignment in assignments:
                    if assignment.user_has_passed(current_user.id):
                        assignment_passed = True
                        break
                
                if assignments:
                    best_assignment = assignments[0]
                    best_score = best_assignment.get_best_score(current_user.id)
                    assignment_info = {
                        'title': best_assignment.title,
                        'passing_score': best_assignment.passing_score,
                        'best_score': best_score,
                        'passed': assignment_passed
                    }
            
            is_course_completed = False
            if assignment_required:
                is_course_completed = assignment_passed
            else:
                is_course_completed = (lessons_percentage == 100)
            
            course_progress_list.append({
                'course_id': course.id,
                'completed': completed_lessons,
                'total': total_lessons,
                'percentage': lessons_percentage,
                'assignment_required': assignment_required,
                'assignment_passed': assignment_passed,
                'assignment_info': assignment_info,
                'is_completed': is_course_completed
            })

        # Get mandatory course IDs for this user
        mandatory_course_ids = set()
        user_mandatory = MandatoryCourse.get_user_mandatory_courses(current_user.id)
        for mc in user_mandatory:
            mandatory_course_ids.add(mc.course_id)

        return render_template('user/dashboard.html',
                               title='Dashboard',
                               courses=available_courses,
                               user_interests=user_interests,
                               recent_activities=recent_activities,
                               bookmarked_lessons=bookmarked_lessons,
                               current_lesson=current_lesson,
                               recommended_courses=recommended_courses,
                               progress_stats=progress_stats,
                               course_progress_list=course_progress_list,
                               mandatory_course_ids=mandatory_course_ids)

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        flash('You have been logged out.', 'info')
        return redirect(url_for('index'))

    @app.route('/admin/users')
    @login_required
    def admin_users():
        if not current_user.is_admin:
            flash('You do not have permission to access the admin area.', 'danger')
            return redirect(url_for('index'))

        users = User.query.filter_by(is_admin=False).all()

        # Get stats for dashboard cards
        stats = {
            'pending_users_count': User.query.filter_by(is_approved=False, is_admin=False).count(),
            'users_count': User.query.filter_by(is_admin=False).count(),
            'courses_count': Course.query.count(),
            'interests_count': Interest.query.count()
        }

        return render_template('admin/users.html',
                               title='Manage Users',
                               users=users,
                               **stats)

    @app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
    @login_required
    def admin_delete_user(user_id):
        if not current_user.is_admin:
            abort(403)

        user = User.query.get_or_404(user_id)
    
        # Prevent admin from deleting themselves
        if user.id == current_user.id:
            flash('You cannot delete your own account.', 'danger')
            return redirect(url_for('admin_users'))
    
        # Prevent deleting other admin users
        if user.is_admin:
            flash('You cannot delete admin users.', 'danger')
            return redirect(url_for('admin_users'))
    
        username = user.username
    
        # Delete user's forum replies first (child records)
        ForumReply.query.filter_by(user_id=user.id).delete()
    
        # Delete user's forum topics
        ForumTopic.query.filter_by(user_id=user.id).delete()
    
        # Now delete the user
        db.session.delete(user)
        db.session.commit()
        flash(f'User "{username}" has been deleted successfully.', 'success')
        return redirect(url_for('admin_users'))

    @app.route('/admin/interests')
    @login_required
    def admin_interests():
        if not current_user.is_admin:
            flash('You do not have permission to access the admin area.', 'danger')
            return redirect(url_for('index'))

        interests = Interest.query.all()

        # Get stats for dashboard cards
        stats = {
            'pending_users_count': User.query.filter_by(is_approved=False, is_admin=False).count(),
            'users_count': User.query.filter_by(is_admin=False).count(),
            'courses_count': Course.query.count(),
            'interests_count': Interest.query.count()
        }

        return render_template('admin/interests.html',
                               title='Manage Interests',
                               interests=interests,
                               **stats)

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if current_user.is_authenticated:
            return redirect(url_for('index'))

        form = RegistrationForm()
        if form.validate_on_submit():
            otp_code = EmailVerificationToken.generate_otp()
            expires_at = datetime.utcnow() + timedelta(minutes=10)
            
            EmailVerificationToken.query.filter_by(email=form.email.data, verified=False).delete()
            
            password_hash = generate_password_hash(form.password.data)
            
            verification_token = EmailVerificationToken(
                email=form.email.data,
                username=form.username.data,
                password_hash=password_hash,
                otp_code=otp_code,
                expires_at=expires_at
            )
            db.session.add(verification_token)
            db.session.commit()
            
            from .utils.email_helpers import send_email_verification_otp
            email_sent = send_email_verification_otp(form.email.data, otp_code, form.username.data)
            
            if email_sent:
                session['verification_email'] = form.email.data
                flash('A verification code has been sent to your email. Please verify your email to continue.', 'success')
                return redirect(url_for('verify_email'))
            else:
                flash('Unable to send verification email. Please check your email address and try again.', 'danger')

        return render_template('auth/register.html', title='Register', form=form)

    @app.route('/verify-email', methods=['GET', 'POST'])
    def verify_email():
        if current_user.is_authenticated:
            return redirect(url_for('index'))
        
        email = session.get('verification_email')
        if not email:
            flash('Please register first.', 'warning')
            return redirect(url_for('register'))
        
        form = EmailVerificationForm()
        if form.validate_on_submit():
            token = EmailVerificationToken.query.filter_by(
                email=email,
                otp_code=form.otp.data,
                verified=False
            ).first()
            
            if token and token.is_valid():
                existing_user = User.query.filter(
                    (User.email == token.email) | (User.username == token.username)
                ).first()
                
                if existing_user:
                    flash('This email or username is already registered. Please login or use different credentials.', 'danger')
                    return redirect(url_for('register'))
                
                user = User(
                    username=token.username,
                    email=token.email,
                    password_hash=token.password_hash
                )
                user.set_access_based_on_domain()
                db.session.add(user)
                
                token.verified = True
                db.session.commit()
                
                user.otp_secret = generate_otp_secret()
                db.session.commit()
                
                session.pop('verification_email', None)
                session['setup_user_id'] = user.id
                
                flash('Email verified successfully! Now please set up two-factor authentication.', 'success')
                return redirect(url_for('setup_2fa'))
            else:
                flash('Invalid or expired verification code. Please try again.', 'danger')
        
        return render_template('auth/verify_email.html', title='Verify Email', form=form, email=email)

    @app.route('/resend-verification')
    def resend_verification():
        if current_user.is_authenticated:
            return redirect(url_for('index'))
        
        email = session.get('verification_email')
        if not email:
            flash('Please register first.', 'warning')
            return redirect(url_for('register'))
        
        token = EmailVerificationToken.query.filter_by(email=email, verified=False).first()
        if not token:
            flash('Please register again.', 'warning')
            return redirect(url_for('register'))
        
        otp_code = EmailVerificationToken.generate_otp()
        expires_at = datetime.utcnow() + timedelta(minutes=10)
        
        token.otp_code = otp_code
        token.expires_at = expires_at
        db.session.commit()
        
        from .utils.email_helpers import send_email_verification_otp
        email_sent = send_email_verification_otp(email, otp_code, token.username)
        
        if email_sent:
            flash('A new verification code has been sent to your email.', 'success')
        else:
            flash('Unable to send verification email. Please try again later.', 'danger')
        
        return redirect(url_for('verify_email'))

    @app.route('/setup-2fa', methods=['GET', 'POST'])
    def setup_2fa():
        if current_user.is_authenticated:
            return redirect(url_for('index'))

        user_id = session.get('setup_user_id')
        if not user_id:
            flash('Invalid session. Please register again.', 'danger')
            return redirect(url_for('register'))

        user = User.query.get(user_id)
        if not user or not user.otp_secret:
            flash('Invalid session. Please register again.', 'danger')
            return redirect(url_for('register'))

        form = TwoFactorForm()
        
        if form.validate_on_submit():
            if verify_totp(user.otp_secret, form.token.data):
                user.is_2fa_enabled = True
                db.session.commit()
                session.pop('setup_user_id', None)
                flash('Two-factor authentication set up successfully! Your account is pending admin approval.', 'success')
                return redirect(url_for('login'))
            else:
                flash('Invalid authentication code. Please try again.', 'danger')

        # Generate QR code for 2FA setup
        qr_code = generate_qr_code(user.username, user.otp_secret)
        
        return render_template('auth/two_factor_setup.html', 
                               title='Set Up Two-Factor Authentication',
                               form=form,
                               qr_code=qr_code,
                               username=user.username,
                               secret=user.otp_secret)

    @app.route('/forgot-password', methods=['GET', 'POST'])
    def forgot_password():
        if current_user.is_authenticated:
            return redirect(url_for('index'))
        
        form = ForgotPasswordForm()
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()
            if user:
                otp_code = PasswordResetToken.generate_otp()
                expires_at = datetime.utcnow() + timedelta(minutes=10)
                
                PasswordResetToken.query.filter_by(user_id=user.id, used=False).update({'used': True})
                
                reset_token = PasswordResetToken(
                    user_id=user.id,
                    otp_code=otp_code,
                    expires_at=expires_at
                )
                db.session.add(reset_token)
                db.session.commit()
                
                from .utils.email_helpers import send_password_reset_email
                email_sent = send_password_reset_email(user.email, otp_code, user.username)
                
                if email_sent:
                    session['reset_email'] = user.email
                    flash('A verification code has been sent to your email.', 'success')
                    return redirect(url_for('verify_reset_otp'))
                else:
                    flash('Unable to send email. Please contact support.', 'danger')
            else:
                flash('If that email exists, a reset code has been sent.', 'info')
        
        return render_template('auth/forgot_password.html', title='Forgot Password', form=form)
    
    @app.route('/verify-reset-otp', methods=['GET', 'POST'])
    def verify_reset_otp():
        if current_user.is_authenticated:
            return redirect(url_for('index'))
        
        email = session.get('reset_email')
        if not email:
            flash('Please request a password reset first.', 'warning')
            return redirect(url_for('forgot_password'))
        
        form = VerifyOTPForm()
        if form.validate_on_submit():
            user = User.query.filter_by(email=email).first()
            if user:
                token = PasswordResetToken.query.filter_by(
                    user_id=user.id,
                    otp_code=form.otp.data,
                    used=False
                ).first()
                
                if token and token.is_valid():
                    session['reset_token_id'] = token.id
                    return redirect(url_for('reset_password'))
                else:
                    flash('Invalid or expired verification code.', 'danger')
            else:
                flash('Invalid request.', 'danger')
        
        return render_template('auth/verify_otp.html', title='Verify Code', form=form, email=email)
    
    @app.route('/reset-password', methods=['GET', 'POST'])
    def reset_password():
        if current_user.is_authenticated:
            return redirect(url_for('index'))
        
        token_id = session.get('reset_token_id')
        if not token_id:
            flash('Please verify your code first.', 'warning')
            return redirect(url_for('forgot_password'))
        
        token = PasswordResetToken.query.get(token_id)
        if not token or not token.is_valid():
            session.pop('reset_token_id', None)
            session.pop('reset_email', None)
            flash('Session expired. Please request a new reset code.', 'warning')
            return redirect(url_for('forgot_password'))
        
        form = ResetPasswordForm()
        if form.validate_on_submit():
            user = token.user
            user.set_password(form.password.data)
            token.used = True
            db.session.commit()
            
            session.pop('reset_token_id', None)
            session.pop('reset_email', None)
            
            flash('Your password has been reset successfully. You can now log in.', 'success')
            return redirect(url_for('login'))
        
        return render_template('auth/reset_password.html', title='Reset Password', form=form)

    @app.route('/forum')
    def forum_index():
        topics = ForumTopic.query.filter_by(course_id=None).order_by(ForumTopic.created_at.desc()).all()
        return render_template('forum/index.html', title='General Forum', topics=topics)

    @app.route('/two-factor', methods=['GET', 'POST'])
    def two_factor_auth():
        if current_user.is_authenticated:
            return redirect(url_for('index'))

        user_id = session.get('user_id')
        if not user_id:
            flash('Session expired. Please log in again.', 'warning')
            return redirect(url_for('login'))

        user = User.query.get(user_id)
        if not user or not user.otp_secret:
            flash('Invalid session. Please log in again.', 'danger')
            return redirect(url_for('login'))

        form = TwoFactorForm()
        if form.validate_on_submit():
            if verify_totp(user.otp_secret, form.token.data):
                login_user(user, remember=session.get('remember_me', False))
                session.pop('user_id', None)
                session.pop('remember_me', None)
                flash('Login successful!', 'success')

                next_page = request.args.get('next')
                if not next_page or urlparse(next_page).netloc != '':
                    next_page = url_for('index')
                return redirect(next_page)
            else:
                flash('Invalid authentication code. Please try again.', 'danger')

        return render_template('auth/two_factor.html', title='Two-Factor Authentication', form=form)

    @app.route('/document-analysis', methods=['GET', 'POST'])
    @login_required
    def document_analysis():
        if request.method == 'POST':
            # Handle file upload
            if 'file' not in request.files:
                return jsonify({'error': 'No file uploaded'})

            file = request.files['file']
            if file.filename == '':
                return jsonify({'error': 'No file selected'})

            try:
                result = analyze_document(file, file.filename)
                return jsonify(result)
            except Exception as e:
                return jsonify({'error': str(e)})

        return render_template('document_analysis.html', title='Document Analysis')

    @app.route('/profile', methods=['GET', 'POST'])
    @login_required
    def profile():
        form = ProfileForm()
        if form.validate_on_submit():
            if form.new_password.data:
                if form.current_password.data and current_user.check_password(form.current_password.data):
                    current_user.set_password(form.new_password.data)
                    flash('Password updated successfully!', 'success')
                else:
                    flash('Current password is incorrect.', 'danger')
                    return render_template('user/profile.html', title='Profile', form=form)

            db.session.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('profile'))

        # Pre-populate form with current user data
        form.username.data = current_user.username
        form.email.data = current_user.email

        return render_template('user/profile.html', title='Profile', form=form)

    @app.route('/user/interests', methods=['GET', 'POST'])
    @login_required
    def user_interests():
        if not current_user.is_approved:
            flash('Your account is pending approval.', 'warning')
            return redirect(url_for('logout'))

        form = InterestSelectionForm()
        all_interests = Interest.query.all()

        # BT users can't see "Fun" interest
        if current_user.email_domain == 'bt.com':
            all_interests = [i for i in all_interests if i.name != 'Fun']

        form.interests.choices = [(i.id, i.name) for i in all_interests]

        # Existing user interests
        existing_interests = UserInterest.query.filter_by(user_id=current_user.id).all()
        interest_map = {ui.interest_id: ui for ui in existing_interests}

        if form.validate_on_submit():
            selected_ids = set(form.interests.data or [])

            for interest in all_interests:
                iid = interest.id
                existing_ui = interest_map.get(iid)

                # --- Granted ---
                if existing_ui and existing_ui.access_granted:
                    continue  # granted interests are always kept

                # --- Pending and still selected ---
                if existing_ui and not existing_ui.access_granted and iid in selected_ids:
                    continue  # keep existing pending

                # --- Pending but now unchecked ---
                if existing_ui and not existing_ui.access_granted and iid not in selected_ids:
                    db.session.delete(existing_ui)
                    continue

                # --- New selection (no existing record, user wants it) ---
                if not existing_ui and iid in selected_ids:
                    new_request = UserInterest(
                        user_id=current_user.id,
                        interest_id=iid,
                        access_granted=False  # pending by default
                    )
                    db.session.add(new_request)

            db.session.commit()
            flash('Your Teams requests have been updated successfully.', 'success')
            return redirect(url_for('user_interests'))

        # --- GET ---
        granted_interests = []
        pending_interests = []
        available_interests = []

        for interest in all_interests:
            ui = interest_map.get(interest.id)
            if ui:
                if ui.access_granted:
                    granted_interests.append(interest)
                else:
                    pending_interests.append(interest)
            else:
                available_interests.append(interest)

        return render_template(
            'user/interests.html',
            title='My Interests',
            form=form,
            granted_interests=granted_interests,
            pending_interests=pending_interests,
            available_interests=available_interests
        )

    @app.route('/courses/<int:course_id>')
    @login_required
    def view_course(course_id):
        course = Course.query.get_or_404(course_id)

        if not user_can_access_course(current_user, course):
            flash('You do not have access to this course.', 'danger')
            return redirect(url_for('user_dashboard'))

        lessons = Lesson.query.filter_by(course_id=course.id).order_by(Lesson.order).all()
        
        lesson_progress = {}
        completed_count = 0
        for lesson in lessons:
            progress = UserLessonProgress.query.filter_by(
                user_id=current_user.id,
                lesson_id=lesson.id
            ).first()
            if progress:
                lesson_progress[lesson.id] = progress.status
                if progress.status == 'completed':
                    completed_count += 1
            else:
                lesson_progress[lesson.id] = 'not_started'
        
        total_lessons = len(lessons)
        course_progress = {
            'total': total_lessons,
            'completed': completed_count,
            'percentage': round((completed_count / total_lessons * 100) if total_lessons > 0 else 0)
        }

        # Check if course is mandatory for this user
        is_mandatory = MandatoryCourse.is_mandatory_for_user(course_id, current_user.id)

        # Get course assignment (final test)
        course_assignment = Assignment.query.filter_by(course_id=course_id, is_active=True).first()
        assignment_passed = False
        assignment_score = None
        if course_assignment:
            best_score = course_assignment.get_best_score(current_user.id)
            if best_score is not None:
                assignment_score = best_score
                assignment_passed = best_score >= course_assignment.passing_score

        return render_template('user/course.html',
                               title=course.title,
                               course=course,
                               lessons=lessons,
                               lesson_progress=lesson_progress,
                               course_progress=course_progress,
                               is_mandatory=is_mandatory,
                               course_assignment=course_assignment,
                               assignment_passed=assignment_passed,
                               assignment_score=assignment_score)

    @app.route('/lessons/<int:lesson_id>')
    @login_required
    def view_lesson(lesson_id):
        lesson = Lesson.query.get_or_404(lesson_id)

        if not user_can_access_course(current_user, lesson.course):
            flash('You do not have access to this lesson.', 'danger')
            return redirect(url_for('user_dashboard'))

        # Get previous and next lessons for navigation
        prev_lesson = Lesson.query.filter(
            Lesson.course_id == lesson.course_id,
            Lesson.order < lesson.order
        ).order_by(Lesson.order.desc()).first()

        next_lesson = Lesson.query.filter(
            Lesson.course_id == lesson.course_id,
            Lesson.order > lesson.order
        ).order_by(Lesson.order.asc()).first()

        # Check if user can view content based on access level
        can_view_content = lesson.can_view_content(current_user)
        
        # Get user's lesson progress
        lesson_progress = UserLessonProgress.query.filter_by(
            user_id=current_user.id,
            lesson_id=lesson.id
        ).first()
        
        # Get user's notes for this lesson
        user_notes = UserNote.query.filter_by(
            user_id=current_user.id,
            lesson_id=lesson.id
        ).order_by(UserNote.created_at.desc()).all()
        
        # Get lesson media items (videos, files, links)
        media_items = LessonMedia.query.filter_by(lesson_id=lesson.id).order_by(LessonMedia.order).all()

        return render_template('user/lesson.html',
                               title=lesson.title,
                               lesson=lesson,
                               course=lesson.course,
                               prev_lesson=prev_lesson,
                               next_lesson=next_lesson,
                               can_view_content=can_view_content,
                               lesson_progress=lesson_progress,
                               user_notes=user_notes,
                               media_items=media_items)

    # Admin routes for managing interests
    @app.route('/admin/interests/add', methods=['GET', 'POST'])
    @login_required
    def admin_add_interest():
        if not current_user.is_admin:
            abort(403)

        form = InterestForm()
        if form.validate_on_submit():
            interest = Interest(
                name=form.name.data,
                description=form.description.data
            )
            db.session.add(interest)
            db.session.commit()
            flash('Teams created successfully!', 'success')
            return redirect(url_for('admin_interests'))

        return render_template('admin/edit_interest.html', title='Add Interest', form=form)

    @app.route('/admin/interests/<int:interest_id>/edit', methods=['GET', 'POST'])
    @login_required
    def admin_edit_interest(interest_id):
        if not current_user.is_admin:
            abort(403)

        interest = Interest.query.get_or_404(interest_id)
        form = InterestForm()

        if form.validate_on_submit():
            interest.name = form.name.data
            interest.description = form.description.data
            db.session.commit()
            flash('Teams updated successfully!', 'success')
            return redirect(url_for('admin_interests'))

        form.name.data = interest.name
        form.description.data = interest.description
        return render_template('admin/edit_interest.html', title='Edit Interest', form=form, interest=interest)

    @app.route('/admin/interests/<int:interest_id>/delete', methods=['POST'])
    @login_required
    def admin_delete_interest(interest_id):
        if not current_user.is_admin:
            abort(403)

        interest = Interest.query.get_or_404(interest_id)
        db.session.delete(interest)
        db.session.commit()
        flash('Teams deleted successfully!', 'success')
        return redirect(url_for('admin_interests'))

    @app.route('/admin/users/<int:user_id>/interests')
    @login_required
    def admin_user_interests(user_id):
        if not current_user.is_admin:
            abort(403)

        user = User.query.get_or_404(user_id)
        interests = Interest.query.all()
        user_interests_status = get_user_interests_status(user_id)
        form = UserInterestAccessForm()
        
        # Debug logging
        import logging
        logger = logging.getLogger(__name__)
        logger.info(f"User {user_id} interests page - Found {len(interests)} total interests")
        logger.info(f"Interest status data: {[(s['interest'].id, s['interest'].name, s['access_granted']) for s in user_interests_status]}")

        return render_template('admin/user_interests.html',
                               title=f'Manage Interests for {user.username}',
                               user=user,
                               interests=interests,
                               interest_status=user_interests_status,
                               form=form)

    @app.route('/admin/users/<int:user_id>/progress')
    @login_required
    def admin_user_progress(user_id):
        if not current_user.is_admin:
            abort(403)

        user = User.query.get_or_404(user_id)
        
        # Get all courses the user has access to via interests
        user_interests = UserInterest.query.filter_by(
            user_id=user_id,
            access_granted=True
        ).all()
        
        interest_ids = [ui.interest_id for ui in user_interests]
        
        course_ids = set()
        
        # Get courses for these interests
        if interest_ids:
            course_interests = CourseInterest.query.filter(
                CourseInterest.interest_id.in_(interest_ids)
            ).all()
            course_ids.update([ci.course_id for ci in course_interests])
        
        # Also get courses from direct enrollments (UserCourse)
        user_courses = UserCourse.query.filter_by(user_id=user_id).all()
        course_ids.update([uc.course_id for uc in user_courses])
        
        # Get all unique courses
        courses = Course.query.filter(Course.id.in_(course_ids)).all() if course_ids else []
        
        # Build progress data for each course
        course_progress_data = []
        total_lessons_all = 0
        completed_lessons_all = 0
        
        for course in courses:
            lessons = Lesson.query.filter_by(course_id=course.id).order_by(Lesson.order).all()
            lesson_data = []
            completed_count = 0
            
            for lesson in lessons:
                progress = UserLessonProgress.query.filter_by(
                    user_id=user_id,
                    lesson_id=lesson.id
                ).first()
                
                status = progress.status if progress else 'not_started'
                completed_at = progress.completed_at if progress and progress.completed_at else None
                
                if status == 'completed':
                    completed_count += 1
                    completed_lessons_all += 1
                
                lesson_data.append({
                    'lesson': lesson,
                    'status': status,
                    'completed_at': completed_at
                })
                total_lessons_all += 1
            
            total = len(lessons)
            percentage = round((completed_count / total * 100) if total > 0 else 0)
            
            course_progress_data.append({
                'course': course,
                'lessons': lesson_data,
                'completed': completed_count,
                'total': total,
                'percentage': percentage
            })
        
        overall_percentage = round((completed_lessons_all / total_lessons_all * 100) if total_lessons_all > 0 else 0)
        
        return render_template('admin/user_progress.html',
                               title=f'Progress for {user.username}',
                               user=user,
                               course_progress=course_progress_data,
                               overall_stats={
                                   'total_courses': len(courses),
                                   'total_lessons': total_lessons_all,
                                   'completed_lessons': completed_lessons_all,
                                   'percentage': overall_percentage
                               })

    @app.route('/admin/user-interest/update', methods=['POST'])
    @login_required
    def admin_update_user_interest():
        if not current_user.is_admin:
            abort(403)

        user_id_str = request.form.get('user_id')
        interest_id = request.form.get('interest_id')
        action = request.form.get('action')

        # Store user_id for redirect
        redirect_user_id = None

        if user_id_str and interest_id and action:
            try:
                user_id = int(user_id_str)
                redirect_user_id = user_id
                interest_id = int(interest_id)

                if action == 'grant':
                    if grant_interest_access(user_id, interest_id):
                        flash('Teams access granted successfully.', 'success')
                    else:
                        flash('Error granting interest access.', 'danger')
                elif action == 'revoke':
                    if revoke_interest_access(user_id, interest_id):
                        flash('Teams access revoked successfully.', 'success')
                    else:
                        flash('Error revoking interest access.', 'danger')
                else:
                    flash('Invalid action specified.', 'danger')
            except ValueError:
                flash('Invalid user or interest ID.', 'danger')
                try:
                    redirect_user_id = int(user_id_str)
                except:
                    redirect_user_id = None
        else:
            flash('Missing required form data.', 'danger')

        # If we have a valid user_id, redirect to their interests page, otherwise to users list
        if redirect_user_id:
            return redirect(url_for('admin_user_interests', user_id=redirect_user_id))
        else:
            return redirect(url_for('admin_users'))

    # Admin course management routes
    @app.route('/admin/courses/add', methods=['GET', 'POST'])
    @login_required
    def admin_add_course():
        if not current_user.is_admin:
            abort(403)

        form = CourseForm()
        interests = Interest.query.all()
        form.interests.choices = [(i.id, i.name) for i in interests]

        if form.validate_on_submit():
            course = Course(
                title=form.title.data,
                description=form.description.data,
                cover_image_url=form.cover_image_url.data,
                issue_certificates=form.issue_certificates.data
            )
            db.session.add(course)
            db.session.flush()  # Get the course ID

            # Add course-interest relationships
            for interest_id in form.interests.data:
                course_interest = CourseInterest(
                    course_id=course.id,
                    interest_id=interest_id
                )
                db.session.add(course_interest)

            db.session.commit()
            flash('Course created successfully!', 'success')
            return redirect(url_for('admin_courses'))

        # Initialize interests data to empty list for new courses
        if form.interests.data is None:
            form.interests.data = []

        return render_template('admin/edit_course.html', title='Add Course', form=form)

    @app.route('/admin/courses/<int:course_id>/edit', methods=['GET', 'POST'])
    @login_required
    def admin_edit_course(course_id):
        if not current_user.is_admin:
            abort(403)

        course = Course.query.get_or_404(course_id)
        form = CourseForm()
        interests = Interest.query.all()
        form.interests.choices = [(i.id, i.name) for i in interests]

        if form.validate_on_submit():
            course.title = form.title.data
            course.description = form.description.data
            course.cover_image_url = form.cover_image_url.data
            course.issue_certificates = form.issue_certificates.data

            # Update course-interest relationships
            CourseInterest.query.filter_by(course_id=course.id).delete()
            for interest_id in form.interests.data:
                course_interest = CourseInterest(
                    course_id=course.id,
                    interest_id=interest_id
                )
                db.session.add(course_interest)

            db.session.commit()
            flash('Course updated successfully!', 'success')
            return redirect(url_for('admin_courses'))

        # Pre-populate form
        form.title.data = course.title
        form.description.data = course.description
        form.cover_image_url.data = course.cover_image_url

        # Set selected interests
        current_interests = [ci.interest_id for ci in CourseInterest.query.filter_by(course_id=course.id).all()]
        form.interests.data = current_interests
        form.issue_certificates.data = course.issue_certificates

        return render_template('admin/edit_course.html', title='Edit Course', form=form, course=course)

    @app.route('/admin/courses/<int:course_id>/delete', methods=['POST'])
    @login_required
    def admin_delete_course(course_id):
        if not current_user.is_admin:
            abort(403)

        course = Course.query.get_or_404(course_id)
        
        try:
            # Delete related records that don't have cascade delete set up
            # Delete course interests
            CourseInterest.query.filter_by(course_id=course_id).delete()
            
            # Delete user course enrollments
            UserCourse.query.filter_by(course_id=course_id).delete()
            
            # Delete mandatory course assignments
            MandatoryCourse.query.filter_by(course_id=course_id).delete()
            
            # Delete user activities related to this course
            UserActivity.query.filter_by(course_id=course_id).delete()
            
            # Get all assignments for this course and delete their attempts first
            assignments = Assignment.query.filter_by(course_id=course_id).all()
            for assignment in assignments:
                UserAssignmentAttempt.query.filter_by(assignment_id=assignment.id).delete()
            
            # Delete assignments (questions cascade automatically)
            Assignment.query.filter_by(course_id=course_id).delete()
            
            # Now delete the course (lessons, forum_topics cascade automatically)
            db.session.delete(course)
            db.session.commit()
            flash('Course deleted successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error deleting course: {str(e)}', 'danger')
        
        return redirect(url_for('admin_courses'))

    # Admin lesson management routes
    @app.route('/admin/courses/<int:course_id>/lessons')
    @login_required
    def admin_lessons(course_id):
        if not current_user.is_admin:
            abort(403)

        course = Course.query.get_or_404(course_id)
        lessons = Lesson.query.filter_by(course_id=course_id).order_by(Lesson.order).all()
        assignments = Assignment.query.filter_by(course_id=course_id).all()

        return render_template('admin/lessons.html',
                               title=f'Manage Lessons for {course.title}',
                               course=course,
                               lessons=lessons,
                               assignments=assignments)

    @app.route('/admin/courses/<int:course_id>/lessons/add', methods=['GET', 'POST'])
    @login_required
    def admin_add_lesson(course_id):
        if not current_user.is_admin:
            abort(403)

        course = Course.query.get_or_404(course_id)
        form = LessonForm()
        
        # Auto-calculate next order number
        max_order = db.session.query(db.func.max(Lesson.order)).filter_by(course_id=course_id).scalar()
        next_order = (max_order or 0) + 1

        if form.validate_on_submit():
            lesson = Lesson(
                title=form.title.data,
                content=form.content.data,
                content_type=form.content_type.data,
                video_url=form.video_url.data,
                order=form.order.data,
                course_id=course_id
            )
            db.session.add(lesson)
            db.session.commit()
            flash('Lesson created successfully! You can now add media to your lesson.', 'success')
            # Redirect to edit page (PRG pattern) so media management is available
            return redirect(url_for('admin_edit_lesson', lesson_id=lesson.id))

        # Set default order for new lessons
        if form.order.data is None or form.order.data == 0:
            form.order.data = next_order

        return render_template('admin/edit_lesson.html', title='Add Lesson', form=form, course=course)

    @app.route('/admin/lessons/<int:lesson_id>/edit', methods=['GET', 'POST'])
    @login_required
    def admin_edit_lesson(lesson_id):
        if not current_user.is_admin:
            abort(403)

        lesson = Lesson.query.get_or_404(lesson_id)
        form = LessonForm()

        if form.validate_on_submit():
            lesson.title = form.title.data
            lesson.content = form.content.data
            lesson.content_type = form.content_type.data
            lesson.video_url = form.video_url.data
            lesson.order = form.order.data
            db.session.commit()
            flash('Lesson updated successfully!', 'success')
            return redirect(url_for('admin_lessons', course_id=lesson.course_id))

        # Pre-populate form
        form.title.data = lesson.title
        form.content.data = lesson.content
        form.content_type.data = lesson.content_type
        form.video_url.data = lesson.video_url
        form.order.data = lesson.order

        media_items = LessonMedia.query.filter_by(lesson_id=lesson.id).order_by(LessonMedia.order).all()
        return render_template('admin/edit_lesson.html', title='Edit Lesson', form=form, lesson=lesson, course=lesson.course, media_items=media_items)

    @app.route('/admin/lessons/<int:lesson_id>/delete', methods=['POST'])
    @login_required
    def admin_delete_lesson(lesson_id):
        if not current_user.is_admin:
            abort(403)

        lesson = Lesson.query.get_or_404(lesson_id)
        course_id = lesson.course_id
        db.session.delete(lesson)
        db.session.commit()
        flash('Lesson deleted successfully!', 'success')
        return redirect(url_for('admin_lessons', course_id=course_id))

    @app.route('/api/lessons/<int:lesson_id>/media', methods=['GET'])
    @login_required
    def get_lesson_media(lesson_id):
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        media_items = LessonMedia.query.filter_by(lesson_id=lesson_id).order_by(LessonMedia.order).all()
        return jsonify({
            'media': [{
                'id': m.id,
                'media_type': m.media_type,
                'title': m.title,
                'url': m.url,
                'file_name': m.file_name,
                'file_size': m.get_file_size_display() if m.file_size else None,
                'order': m.order
            } for m in media_items]
        })

    @app.route('/api/lessons/<int:lesson_id>/media/youtube', methods=['POST'])
    @login_required
    def add_youtube_video(lesson_id):
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        lesson = Lesson.query.get_or_404(lesson_id)
        data = request.get_json()
        
        if not data or not data.get('url'):
            return jsonify({'error': 'YouTube URL is required'}), 400
        
        max_order = db.session.query(db.func.max(LessonMedia.order)).filter_by(lesson_id=lesson_id).scalar() or 0
        
        media = LessonMedia(
            lesson_id=lesson_id,
            media_type='youtube',
            title=data.get('title', 'YouTube Video'),
            url=data['url'],
            order=max_order + 1
        )
        db.session.add(media)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'media': {
                'id': media.id,
                'media_type': media.media_type,
                'title': media.title,
                'url': media.url,
                'embed_url': media.get_youtube_embed_url(),
                'order': media.order
            }
        })

    @app.route('/api/lessons/<int:lesson_id>/media/link', methods=['POST'])
    @login_required
    def add_external_link(lesson_id):
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        lesson = Lesson.query.get_or_404(lesson_id)
        data = request.get_json()
        
        if not data or not data.get('url'):
            return jsonify({'error': 'URL is required'}), 400
        
        max_order = db.session.query(db.func.max(LessonMedia.order)).filter_by(lesson_id=lesson_id).scalar() or 0
        
        media = LessonMedia(
            lesson_id=lesson_id,
            media_type='link',
            title=data.get('title', 'External Link'),
            url=data['url'],
            order=max_order + 1
        )
        db.session.add(media)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'media': {
                'id': media.id,
                'media_type': media.media_type,
                'title': media.title,
                'url': media.url,
                'order': media.order
            }
        })

    @app.route('/api/lessons/<int:lesson_id>/media/file', methods=['POST'])
    @login_required
    def upload_lesson_file(lesson_id):
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        lesson = Lesson.query.get_or_404(lesson_id)
        
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        allowed_extensions = {'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'zip', 'rar', 'png', 'jpg', 'jpeg', 'gif'}
        ext = file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else ''
        
        if ext not in allowed_extensions:
            return jsonify({'error': f'File type not allowed. Allowed: {", ".join(allowed_extensions)}'}), 400
        
        filename = secure_filename(file.filename)
        unique_filename = f"{lesson_id}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{filename}"
        
        upload_folder = os.path.join(app.static_folder, 'uploads', 'lessons')
        os.makedirs(upload_folder, exist_ok=True)
        
        file_path = os.path.join(upload_folder, unique_filename)
        file.save(file_path)
        
        file_size = os.path.getsize(file_path)
        
        max_order = db.session.query(db.func.max(LessonMedia.order)).filter_by(lesson_id=lesson_id).scalar() or 0
        
        media = LessonMedia(
            lesson_id=lesson_id,
            media_type='file',
            title=request.form.get('title', filename),
            file_path=f'uploads/lessons/{unique_filename}',
            file_name=filename,
            file_size=file_size,
            order=max_order + 1
        )
        db.session.add(media)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'media': {
                'id': media.id,
                'media_type': media.media_type,
                'title': media.title,
                'file_name': media.file_name,
                'file_size': media.get_file_size_display(),
                'order': media.order
            }
        })

    @app.route('/api/lessons/media/<int:media_id>', methods=['DELETE'])
    @login_required
    def delete_lesson_media(media_id):
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        media = LessonMedia.query.get_or_404(media_id)
        
        if media.media_type == 'file' and media.file_path:
            file_path = os.path.join(app.static_folder, media.file_path)
            if os.path.exists(file_path):
                os.remove(file_path)
        
        db.session.delete(media)
        db.session.commit()
        
        return jsonify({'success': True})

    @app.route('/api/lessons/media/<int:media_id>', methods=['PUT'])
    @login_required
    def update_lesson_media(media_id):
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        
        media = LessonMedia.query.get_or_404(media_id)
        data = request.get_json()
        
        if data.get('title'):
            media.title = data['title']
        if data.get('url') and media.media_type in ['youtube', 'link']:
            media.url = data['url']
        if data.get('order') is not None:
            media.order = data['order']
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'media': {
                'id': media.id,
                'media_type': media.media_type,
                'title': media.title,
                'url': media.url,
                'order': media.order
            }
        })

    # Forum routes
    @app.route('/forum/new', methods=['GET', 'POST'])
    @login_required
    def forum_new_topic():
        form = ForumTopicForm()

        if form.validate_on_submit():
            topic = ForumTopic(
                title=form.title.data,
                content=form.content.data,
                course_id=form.course_id.data if form.course_id.data else None,
                user_id=current_user.id
            )
            db.session.add(topic)
            db.session.commit()
            flash('Topic created successfully!', 'success')

            if topic.course_id:
                return redirect(url_for('course_forum', course_id=topic.course_id))
            else:
                return redirect(url_for('forum_index'))

        return render_template('forum/new_topic.html', title='New Topic', form=form)

    @app.route('/forum/topic/<int:topic_id>')
    @login_required
    def forum_topic(topic_id):
        topic = ForumTopic.query.get_or_404(topic_id)
        replies = ForumReply.query.filter_by(topic_id=topic_id).order_by(ForumReply.created_at).all()
        form = ForumReplyForm()

        return render_template('forum/topic.html',
                               title=topic.title,
                               topic=topic,
                               replies=replies,
                               form=form)

    @app.route('/forum/topic/<int:topic_id>/reply', methods=['POST'])
    @login_required
    def forum_reply(topic_id):
        topic = ForumTopic.query.get_or_404(topic_id)
        form = ForumReplyForm()

        if form.validate_on_submit():
            reply = ForumReply(
                content=form.content.data,
                topic_id=topic_id,
                user_id=current_user.id
            )
            db.session.add(reply)
            db.session.commit()
            flash('Reply posted successfully!', 'success')

        return redirect(url_for('forum_topic', topic_id=topic_id))

    @app.route('/courses/<int:course_id>/forum')
    @login_required
    def course_forum(course_id):
        course = Course.query.get_or_404(course_id)

        if not user_can_access_course(current_user, course):
            flash('You do not have access to this course forum.', 'danger')
            return redirect(url_for('user_dashboard'))

        topics = ForumTopic.query.filter_by(course_id=course_id).order_by(ForumTopic.created_at.desc()).all()

        return render_template('forum/course_forum.html',
                               title=f'{course.title} Forum',
                               course=course,
                               topics=topics)

    # Admin interest requests management
    @app.route('/admin/interest-requests')
    @login_required
    def admin_user_interest_requests():
        if not current_user.is_admin:
            abort(403)

        # Get all user interests that are not yet granted access
        pending_requests = db.session.query(UserInterest, User, Interest).join(
            User, UserInterest.user_id == User.id
        ).join(
            Interest, UserInterest.interest_id == Interest.id
        ).filter(UserInterest.access_granted == False).all()

        # Convert to a list of objects with user and interest attributes
        pending_list = []
        for ui, user, interest in pending_requests:
            pending_list.append({
                'user': user,
                'interest': interest,
                'user_interest': ui
            })

        # Get stats for dashboard cards
        stats = {
            'pending_users_count': User.query.filter_by(is_approved=False, is_admin=False).count(),
            'users_count': User.query.filter_by(is_admin=False).count(),
            'courses_count': Course.query.count(),
            'interests_count': Interest.query.count()
        }

        return render_template('admin/user_interest_requests.html',
                               title='User Interest Requests',
                               pending_requests=pending_list,
                               **stats)

    @app.route('/admin/approve-interest-request', methods=['POST'])
    @login_required
    def admin_approve_interest_request():
        if not current_user.is_admin:
            abort(403)

        user_id = request.form.get('user_id')
        interest_id = request.form.get('interest_id')
        action = request.form.get('action')

        print(f"DEBUG: Individual action - user_id: {user_id}, interest_id: {interest_id}, action: {action}")

        if not user_id or not interest_id or not action:
            flash('Missing required form data. Please try again.', 'danger')
            return redirect(url_for('admin_user_interest_requests'))

        try:
            user_id = int(user_id)
            interest_id = int(interest_id)

            # Check if the user interest record exists
            user_interest = UserInterest.query.filter_by(
                user_id=user_id,
                interest_id=interest_id,
                access_granted=False
            ).first()

            if not user_interest:
                flash('Teams request not found or already processed.', 'warning')
                return redirect(url_for('admin_user_interest_requests'))

            if action == 'approve':
                if grant_interest_access(user_id, interest_id):
                    # Get user and interest names for the flash message
                    user = User.query.get(user_id)
                    interest = Interest.query.get(interest_id)
                    flash(f'Teams access approved for {user.username} - {interest.name}.', 'success')
                else:
                    flash('Error approving interest access.', 'danger')
            elif action == 'reject':
                # Get user and interest names for the flash message before deletion
                user = User.query.get(user_id)
                interest = Interest.query.get(interest_id)
                
                db.session.delete(user_interest)
                db.session.commit()
                flash(f'Teams request rejected for {user.username} - {interest.name}.', 'success')
            else:
                flash('Invalid action specified.', 'danger')
                
        except ValueError as e:
            print(f"DEBUG: ValueError in individual action: {e}")
            flash('Invalid user or interest ID format.', 'danger')
        except Exception as e:
            print(f"DEBUG: Exception in individual action: {e}")
            db.session.rollback()
            flash('An error occurred while processing the request.', 'danger')

        return redirect(url_for('admin_user_interest_requests'))

    @app.route('/admin/bulk-interest-requests', methods=['POST'])
    @login_required
    def admin_bulk_interest_requests():
        if not current_user.is_admin:
            abort(403)

        selected_requests = request.form.getlist('selected_requests')
        bulk_action = request.form.get('bulk_action')

        print(f"DEBUG: Selected requests: {selected_requests}")
        print(f"DEBUG: Bulk action: {bulk_action}")

        if not selected_requests:
            flash('No requests selected. Please select at least one request.', 'warning')
            return redirect(url_for('admin_user_interest_requests'))

        if not bulk_action:
            flash('Invalid action specified.', 'warning')
            return redirect(url_for('admin_user_interest_requests'))

        success_count = 0
        error_count = 0

        for request_id in selected_requests:
            try:
                # Handle individual interest request (format: user_id_interest_id)
                parts = request_id.split('_')
                print(f"DEBUG: Processing request_id: {request_id}, parts: {parts}")
                
                if len(parts) == 2:
                    user_id, interest_id = int(parts[0]), int(parts[1])
                    user_interest = UserInterest.query.filter_by(
                        user_id=user_id,
                        interest_id=interest_id,
                        access_granted=False
                    ).first()

                    print(f"DEBUG: Found user_interest: {user_interest is not None}")

                    if user_interest:
                        if bulk_action == 'approve':
                            if grant_interest_access(user_id, interest_id):
                                success_count += 1
                                print(f"DEBUG: Successfully approved {user_id}_{interest_id}")
                            else:
                                error_count += 1
                                print(f"DEBUG: Failed to approve {user_id}_{interest_id}")
                        elif bulk_action == 'reject':
                            db.session.delete(user_interest)
                            success_count += 1
                            print(f"DEBUG: Successfully rejected {user_id}_{interest_id}")
                    else:
                        error_count += 1
                        print(f"DEBUG: UserInterest not found for {user_id}_{interest_id}")
                else:
                    error_count += 1
                    print(f"DEBUG: Invalid request_id format: {request_id}")

            except (ValueError, AttributeError) as e:
                error_count += 1
                print(f"DEBUG: Exception processing {request_id}: {e}")

        try:
            db.session.commit()
            print(f"DEBUG: Database committed successfully")
        except Exception as e:
            db.session.rollback()
            print(f"DEBUG: Database commit failed: {e}")
            flash('Database error occurred. Please try again.', 'danger')
            return redirect(url_for('admin_user_interest_requests'))

        if success_count > 0:
            action_word = 'approved' if bulk_action == 'approve' else 'rejected'
            flash(f'Successfully {action_word} {success_count} Teams request(s).', 'success')
        if error_count > 0:
            flash(f'Failed to process {error_count} request(s).', 'warning')

        return redirect(url_for('admin_user_interest_requests'))
    
    # API endpoints for interactive learning features
    @app.route('/api/toggle_bookmark/<int:lesson_id>', methods=['POST'])
    @login_required
    def api_toggle_bookmark(lesson_id):
        lesson = Lesson.query.get_or_404(lesson_id)
        
        # Check if user has access to this lesson
        if not user_can_access_course(current_user, lesson.course):
            return jsonify({'error': 'Access denied'}), 403
        
        # Check if bookmark exists
        bookmark = UserBookmark.query.filter_by(
            user_id=current_user.id,
            lesson_id=lesson_id
        ).first()
        
        if bookmark:
            # Remove bookmark
            db.session.delete(bookmark)
            is_bookmarked = False
            
            # Log activity
            activity = UserActivity(
                user_id=current_user.id,
                activity_type='bookmark_removed',
                lesson_id=lesson_id,
                course_id=lesson.course_id,
                activity_data='{"lesson_title": "' + lesson.title + '"}'
            )
            db.session.add(activity)
        else:
            # Add bookmark
            bookmark = UserBookmark(
                user_id=current_user.id,
                lesson_id=lesson_id
            )
            db.session.add(bookmark)
            is_bookmarked = True
            
            # Log activity
            activity = UserActivity(
                user_id=current_user.id,
                activity_type='bookmark_added',
                lesson_id=lesson_id,
                course_id=lesson.course_id,
                activity_data='{"lesson_title": "' + lesson.title + '"}'
            )
            db.session.add(activity)
        
        db.session.commit()
        return jsonify({'success': True, 'is_bookmarked': is_bookmarked})
    
    @app.route('/api/check_bookmark/<int:lesson_id>')
    @login_required
    def api_check_bookmark(lesson_id):
        lesson = Lesson.query.get_or_404(lesson_id)
        
        # Check if user has access to this lesson
        if not user_can_access_course(current_user, lesson.course):
            return jsonify({'error': 'Access denied'}), 403
        
        bookmark = UserBookmark.query.filter_by(
            user_id=current_user.id,
            lesson_id=lesson_id
        ).first()
        
        return jsonify({'is_bookmarked': bookmark is not None})
    
    @app.route('/api/mark_lesson_complete/<int:lesson_id>', methods=['POST'])
    @login_required
    def api_mark_lesson_complete(lesson_id):
        lesson = Lesson.query.get_or_404(lesson_id)
        
        # Check if user has access to this lesson
        if not user_can_access_course(current_user, lesson.course):
            return jsonify({'error': 'Access denied'}), 403
        
        # Get or create progress record
        progress = UserLessonProgress.query.filter_by(
            user_id=current_user.id,
            lesson_id=lesson_id
        ).first()
        
        if not progress:
            progress = UserLessonProgress(
                user_id=current_user.id,
                lesson_id=lesson_id,
                status='completed',
                started_at=datetime.utcnow(),
                completed_at=datetime.utcnow()
            )
            db.session.add(progress)
        else:
            progress.status = 'completed'
            progress.completed_at = datetime.utcnow()
        
        # Log activity
        activity = UserActivity(
            user_id=current_user.id,
            activity_type='lesson_completed',
            lesson_id=lesson_id,
            course_id=lesson.course_id,
            activity_data='{"lesson_title": "' + lesson.title + '"}'
        )
        db.session.add(activity)
        
        db.session.commit()
        return jsonify({'success': True, 'status': 'completed'})
    
    @app.route('/api/mark_lesson_progress/<int:lesson_id>', methods=['POST'])
    @login_required
    def api_mark_lesson_progress(lesson_id):
        lesson = Lesson.query.get_or_404(lesson_id)
        
        # Check if user has access to this lesson
        if not user_can_access_course(current_user, lesson.course):
            return jsonify({'error': 'Access denied'}), 403
        
        data = request.get_json()
        status = data.get('status', 'in_progress')
        
        # Get or create progress record
        progress = UserLessonProgress.query.filter_by(
            user_id=current_user.id,
            lesson_id=lesson_id
        ).first()
        
        if not progress:
            progress = UserLessonProgress(
                user_id=current_user.id,
                lesson_id=lesson_id,
                status=status,
                started_at=datetime.utcnow() if status == 'in_progress' else None,
                last_interaction=datetime.utcnow()
            )
            db.session.add(progress)
            
            # Log activity for first time starting
            if status == 'in_progress':
                activity = UserActivity(
                    user_id=current_user.id,
                    activity_type='lesson_started',
                    lesson_id=lesson_id,
                    course_id=lesson.course_id,
                    activity_data='{"lesson_title": "' + lesson.title + '"}'
                )
                db.session.add(activity)
        else:
            # Only update if not already completed
            if progress.status != 'completed':
                progress.status = status
                progress.last_interaction = datetime.utcnow()
                if status == 'in_progress' and not progress.started_at:
                    progress.started_at = datetime.utcnow()
        
        db.session.commit()
        return jsonify({'success': True, 'status': progress.status})
    
    @app.route('/api/save_note/<int:lesson_id>', methods=['POST'])
    @login_required
    def api_save_note(lesson_id):
        lesson = Lesson.query.get_or_404(lesson_id)
        
        # Check if user has access to this lesson
        if not user_can_access_course(current_user, lesson.course):
            return jsonify({'error': 'Access denied'}), 403
        
        data = request.get_json()
        note_text = data.get('note_text', '').strip()
        
        if not note_text:
            return jsonify({'error': 'Note text cannot be empty'}), 400
        
        # Create note
        note = UserNote(
            user_id=current_user.id,
            lesson_id=lesson_id,
            note_text=note_text
        )
        db.session.add(note)
        
        # Log activity
        activity = UserActivity(
            user_id=current_user.id,
            activity_type='note_added',
            lesson_id=lesson_id,
            course_id=lesson.course_id,
            activity_data='{"lesson_title": "' + lesson.title + '"}'
        )
        db.session.add(activity)
        
        db.session.commit()
        return jsonify({'success': True, 'note_id': note.id})
    
    @app.route('/api/delete_note/<int:note_id>', methods=['DELETE'])
    @login_required
    def api_delete_note(note_id):
        note = UserNote.query.get_or_404(note_id)
        
        # Check if user owns this note
        if note.user_id != current_user.id:
            return jsonify({'error': 'Access denied'}), 403
        
        db.session.delete(note)
        db.session.commit()
        return jsonify({'success': True})

    # ==================== MANDATORY COURSES ADMIN ROUTES ====================
    
    @app.route('/admin/mandatory-courses')
    @login_required
    def admin_mandatory_courses():
        if not current_user.is_admin:
            flash('You do not have permission to access the admin area.', 'danger')
            return redirect(url_for('index'))
        
        # Get all mandatory course assignments
        mandatory_assignments = MandatoryCourse.query.all()
        
        # Get stats for dashboard cards
        stats = {
            'pending_users_count': User.query.filter_by(is_approved=False, is_admin=False).count(),
            'users_count': User.query.filter_by(is_admin=False).count(),
            'courses_count': Course.query.count(),
            'interests_count': Interest.query.count()
        }
        
        return render_template('admin/mandatory_courses.html',
                               title='Mandatory Courses',
                               mandatory_assignments=mandatory_assignments,
                               now=datetime.utcnow(),
                               **stats)
    
    @app.route('/admin/mandatory-courses/add', methods=['GET', 'POST'])
    @login_required
    def admin_add_mandatory_course():
        if not current_user.is_admin:
            abort(403)
        
        form = MandatoryCourseForm()
        courses = Course.query.all()
        users = User.query.filter_by(is_admin=False, is_approved=True).all()
        
        form.course_ids.choices = [(c.id, c.title) for c in courses]
        form.user_ids.choices = [(u.id, f"{u.username} ({u.email})") for u in users]
        
        if form.validate_on_submit():
            deadline = datetime.utcnow() + timedelta(days=form.deadline_days.data) if form.deadline_days.data else None
            
            added_courses = 0
            skipped_courses = 0
            
            requires_redo = form.requires_redo.data
            
            if form.assignment_type.data == 'all':
                # Assign selected courses to all users
                courses_to_notify = []
                for course_id in (form.course_ids.data or []):
                    existing = MandatoryCourse.query.filter_by(course_id=course_id, user_id=None).first()
                    if existing:
                        skipped_courses += 1
                    else:
                        mandatory = MandatoryCourse(
                            course_id=course_id,
                            user_id=None,
                            deadline=deadline,
                            assigned_by=current_user.id,
                            requires_redo=requires_redo
                        )
                        db.session.add(mandatory)
                        added_courses += 1
                        courses_to_notify.append(Course.query.get(course_id))
                        
                        # If requires_redo, reset progress for all users
                        if requires_redo:
                            course = Course.query.get(course_id)
                            if course:
                                lessons = Lesson.query.filter_by(course_id=course_id).all()
                                for lesson in lessons:
                                    UserLessonProgress.query.filter_by(lesson_id=lesson.id).delete()
                
                db.session.commit()
                
                # Send email notifications to all approved non-admin users
                if courses_to_notify:
                    from .utils.email_helpers import send_mandatory_course_email
                    all_users = User.query.filter_by(is_admin=False, is_approved=True).all()
                    emails_sent = 0
                    for course in courses_to_notify:
                        if course:
                            for user in all_users:
                                if send_mandatory_course_email(user.email, user.username, course.title, deadline):
                                    emails_sent += 1
                    if emails_sent > 0:
                        flash(f'Email notifications sent to {len(all_users)} user(s).', 'info')
                
                if added_courses > 0:
                    flash(f'{added_courses} course(s) set as mandatory for all users!', 'success')
                if skipped_courses > 0:
                    flash(f'{skipped_courses} course(s) were already mandatory for all users.', 'warning')
            else:
                # Assign selected courses to specific users
                total_assignments = 0
                notifications_to_send = []  # List of (user, course, deadline) tuples
                for course_id in (form.course_ids.data or []):
                    for user_id in (form.user_ids.data or []):
                        existing = MandatoryCourse.query.filter_by(course_id=course_id, user_id=user_id).first()
                        if not existing:
                            mandatory = MandatoryCourse(
                                course_id=course_id,
                                user_id=user_id,
                                deadline=deadline,
                                assigned_by=current_user.id,
                                requires_redo=requires_redo
                            )
                            db.session.add(mandatory)
                            total_assignments += 1
                            
                            # Queue notification
                            user = User.query.get(user_id)
                            course = Course.query.get(course_id)
                            if user and course:
                                notifications_to_send.append((user, course, deadline))
                            
                            # If requires_redo, reset progress for this user
                            if requires_redo:
                                lessons = Lesson.query.filter_by(course_id=course_id).all()
                                for lesson in lessons:
                                    UserLessonProgress.query.filter_by(
                                        lesson_id=lesson.id,
                                        user_id=user_id
                                    ).delete()
                
                db.session.commit()
                
                # Send email notifications
                if notifications_to_send:
                    from .utils.email_helpers import send_mandatory_course_email
                    emails_sent = 0
                    for user, course, dl in notifications_to_send:
                        if send_mandatory_course_email(user.email, user.username, course.title, dl):
                            emails_sent += 1
                    if emails_sent > 0:
                        flash(f'Email notifications sent for {emails_sent} assignment(s).', 'info')
                
                course_count = len(form.course_ids.data or [])
                user_count = len(form.user_ids.data or [])
                flash(f'{course_count} course(s) set as mandatory for {user_count} user(s)! ({total_assignments} new assignments)', 'success')
            
            return redirect(url_for('admin_mandatory_courses'))
        
        return render_template('admin/add_mandatory_course.html', title='Add Mandatory Courses', form=form)
    
    @app.route('/admin/mandatory-courses/<int:assignment_id>/delete', methods=['POST'])
    @login_required
    def admin_delete_mandatory_course(assignment_id):
        if not current_user.is_admin:
            abort(403)
        
        assignment = MandatoryCourse.query.get_or_404(assignment_id)
        db.session.delete(assignment)
        db.session.commit()
        flash('Mandatory course assignment removed successfully!', 'success')
        return redirect(url_for('admin_mandatory_courses'))
    
    @app.route('/admin/mandatory-courses/completion')
    @login_required
    def admin_mandatory_completion():
        if not current_user.is_admin:
            flash('You do not have permission to access the admin area.', 'danger')
            return redirect(url_for('index'))
        
        # Get all mandatory courses
        mandatory_courses = MandatoryCourse.query.all()
        
        # Build completion data
        completion_data = []
        
        # Get unique course IDs from mandatory assignments
        course_ids = set()
        for mc in mandatory_courses:
            course_ids.add(mc.course_id)
        
        for course_id in course_ids:
            course = Course.query.get(course_id)
            if not course:
                continue
            
            # Get lessons in this course
            lessons = Lesson.query.filter_by(course_id=course_id).all()
            total_lessons = len(lessons)
            
            # Check if mandatory for all or specific users
            global_mandatory = MandatoryCourse.query.filter_by(course_id=course_id, user_id=None).first()
            specific_mandatories = MandatoryCourse.query.filter(
                MandatoryCourse.course_id == course_id,
                MandatoryCourse.user_id != None
            ).all()
            
            # Get users who must complete this course
            if global_mandatory:
                target_users = User.query.filter_by(is_admin=False, is_approved=True).all()
                deadline = global_mandatory.deadline
            else:
                target_user_ids = [m.user_id for m in specific_mandatories]
                target_users = User.query.filter(User.id.in_(target_user_ids)).all()
                deadline = specific_mandatories[0].deadline if specific_mandatories else None
            
            user_completions = []
            for user in target_users:
                # Count completed lessons for this user in this course
                completed_count = UserLessonProgress.query.filter(
                    UserLessonProgress.user_id == user.id,
                    UserLessonProgress.lesson_id.in_([l.id for l in lessons]),
                    UserLessonProgress.status == 'completed'
                ).count() if lessons else 0
                
                is_completed = completed_count == total_lessons and total_lessons > 0
                
                user_completions.append({
                    'user': user,
                    'completed_lessons': completed_count,
                    'total_lessons': total_lessons,
                    'is_completed': is_completed,
                    'completion_percentage': (completed_count / total_lessons * 100) if total_lessons > 0 else 0
                })
            
            completion_data.append({
                'course': course,
                'is_global': global_mandatory is not None,
                'deadline': deadline,
                'user_completions': user_completions,
                'total_users': len(target_users),
                'completed_users': sum(1 for uc in user_completions if uc['is_completed'])
            })
        
        # Get stats for dashboard cards
        stats = {
            'pending_users_count': User.query.filter_by(is_approved=False, is_admin=False).count(),
            'users_count': User.query.filter_by(is_admin=False).count(),
            'courses_count': Course.query.count(),
            'interests_count': Interest.query.count()
        }
        
        return render_template('admin/mandatory_completion.html',
                               title='Mandatory Course Completion',
                               completion_data=completion_data,
                               **stats)
    
    # ==================== ASSIGNMENTS ADMIN ROUTES ====================
    
    @app.route('/admin/assignments')
    @login_required
    def admin_assignments():
        if not current_user.is_admin:
            flash('You do not have permission to access the admin area.', 'danger')
            return redirect(url_for('index'))
        
        assignments = Assignment.query.order_by(Assignment.created_at.desc()).all()
        
        stats = {
            'pending_users_count': User.query.filter_by(is_approved=False, is_admin=False).count(),
            'users_count': User.query.filter_by(is_admin=False).count(),
            'courses_count': Course.query.count(),
            'interests_count': Interest.query.count()
        }
        
        return render_template('admin/assignments.html',
                               title='Assignments',
                               assignments=assignments,
                               **stats)
    
    @app.route('/admin/courses/<int:course_id>/assignments/add', methods=['GET', 'POST'])
    @login_required
    def admin_add_assignment(course_id):
        if not current_user.is_admin:
            abort(403)
        
        course = Course.query.get_or_404(course_id)
        
        assignment = Assignment(
            course_id=course_id,
            title=f"New Assignment - {course.title}",
            description="",
            passing_score=70,
            time_limit_minutes=None,
            max_attempts=0,
            is_active=False,
            created_by=current_user.id
        )
        db.session.add(assignment)
        db.session.commit()
        flash('New assignment created! Please configure the settings and add questions.', 'info')
        return redirect(url_for('admin_edit_assignment', assignment_id=assignment.id))
    
    @app.route('/admin/assignments/<int:assignment_id>/edit', methods=['GET', 'POST'])
    @login_required
    def admin_edit_assignment(assignment_id):
        if not current_user.is_admin:
            abort(403)
        
        assignment = Assignment.query.get_or_404(assignment_id)
        form = AssignmentForm(obj=assignment)
        
        if request.method == 'POST':
            if form.validate_on_submit():
                assignment.title = form.title.data
                assignment.description = form.description.data
                assignment.passing_score = form.passing_score.data
                assignment.time_limit_minutes = form.time_limit_minutes.data if form.time_limit_minutes.data and form.time_limit_minutes.data > 0 else None
                assignment.max_attempts = form.max_attempts.data
                assignment.is_active = form.is_active.data
                db.session.commit()
                flash('Assignment updated successfully!', 'success')
                return redirect(url_for('admin_edit_assignment', assignment_id=assignment.id))
            else:
                # Show form validation errors
                for field, errors in form.errors.items():
                    for error in errors:
                        flash(f'{error}', 'danger')
        
        questions = Question.query.filter_by(assignment_id=assignment_id).order_by(Question.order).all()
        
        return render_template('admin/edit_assignment.html',
                               title='Edit Assignment',
                               form=form,
                               assignment=assignment,
                               questions=questions)
    
    @app.route('/admin/assignments/<int:assignment_id>/delete', methods=['POST'])
    @login_required
    def admin_delete_assignment(assignment_id):
        if not current_user.is_admin:
            abort(403)
        
        assignment = Assignment.query.get_or_404(assignment_id)
        course_id = assignment.course_id
        db.session.delete(assignment)
        db.session.commit()
        flash('Assignment deleted successfully!', 'success')
        return redirect(url_for('admin_lessons', course_id=course_id))
    
    @app.route('/admin/assignments/<int:assignment_id>/questions')
    @login_required
    def admin_manage_questions(assignment_id):
        if not current_user.is_admin:
            abort(403)
        
        assignment = Assignment.query.get_or_404(assignment_id)
        questions = Question.query.filter_by(assignment_id=assignment_id).order_by(Question.order).all()
        
        return render_template('admin/manage_questions.html',
                               title='Manage Questions',
                               assignment=assignment,
                               questions=questions)
    
    @app.route('/admin/assignments/<int:assignment_id>/questions/add', methods=['GET', 'POST'])
    @login_required
    def admin_add_question(assignment_id):
        if not current_user.is_admin:
            abort(403)
        
        assignment = Assignment.query.get_or_404(assignment_id)
        form = QuestionForm()
        
        if form.validate_on_submit():
            max_order = db.session.query(db.func.max(Question.order)).filter_by(assignment_id=assignment_id).scalar() or 0
            
            question = Question(
                assignment_id=assignment_id,
                question_text=form.question_text.data,
                option_a=form.option_a.data,
                option_b=form.option_b.data,
                option_c=form.option_c.data if form.option_c.data else None,
                option_d=form.option_d.data if form.option_d.data else None,
                correct_answer=form.correct_answer.data,
                explanation=form.explanation.data,
                points=form.points.data,
                order=max_order + 1
            )
            db.session.add(question)
            db.session.commit()
            flash('Question added successfully!', 'success')
            return redirect(url_for('admin_edit_assignment', assignment_id=assignment_id))
        
        return render_template('admin/add_question.html',
                               title='Add Question',
                               form=form,
                               assignment=assignment)
    
    @app.route('/admin/questions/<int:question_id>/edit', methods=['GET', 'POST'])
    @login_required
    def admin_edit_question(question_id):
        if not current_user.is_admin:
            abort(403)
        
        question = Question.query.get_or_404(question_id)
        form = QuestionForm(obj=question)
        
        if form.validate_on_submit():
            question.question_text = form.question_text.data
            question.option_a = form.option_a.data
            question.option_b = form.option_b.data
            question.option_c = form.option_c.data if form.option_c.data else None
            question.option_d = form.option_d.data if form.option_d.data else None
            question.correct_answer = form.correct_answer.data
            question.explanation = form.explanation.data
            question.points = form.points.data
            db.session.commit()
            flash('Question updated successfully!', 'success')
            return redirect(url_for('admin_edit_assignment', assignment_id=question.assignment_id))
        
        return render_template('admin/edit_question.html',
                               title='Edit Question',
                               form=form,
                               question=question)
    
    @app.route('/admin/questions/<int:question_id>/delete', methods=['POST'])
    @login_required
    def admin_delete_question(question_id):
        if not current_user.is_admin:
            abort(403)
        
        question = Question.query.get_or_404(question_id)
        assignment_id = question.assignment_id
        db.session.delete(question)
        db.session.commit()
        flash('Question deleted successfully!', 'success')
        return redirect(url_for('admin_edit_assignment', assignment_id=assignment_id))
    
    # ==================== USER ASSIGNMENT ROUTES ====================
    
    @app.route('/courses/<int:course_id>/assignments')
    @login_required
    def course_assignments(course_id):
        course = Course.query.get_or_404(course_id)
        
        if not user_can_access_course(current_user, course):
            flash('You do not have access to this course.', 'danger')
            return redirect(url_for('user_dashboard'))
        
        assignments = Assignment.query.filter_by(course_id=course_id, is_active=True).all()
        
        assignment_status = []
        for assignment in assignments:
            # Only show assignments that have questions
            question_count = assignment.questions.count()
            if question_count == 0:
                continue
                
            best_score = assignment.get_best_score(current_user.id)
            attempts = assignment.get_user_attempts(current_user.id)
            has_passed = assignment.user_has_passed(current_user.id)
            
            assignment_status.append({
                'assignment': assignment,
                'best_score': best_score,
                'attempts_count': len(attempts),
                'has_passed': has_passed,
                'can_attempt': assignment.max_attempts == 0 or len(attempts) < assignment.max_attempts
            })
        
        return render_template('user/course_assignments.html',
                               title=f'{course.title} - Assignments',
                               course=course,
                               assignment_status=assignment_status)
    
    @app.route('/assignments/<int:assignment_id>/start', methods=['GET', 'POST'])
    @login_required
    def start_assignment(assignment_id):
        assignment = Assignment.query.get_or_404(assignment_id)
        
        if not user_can_access_course(current_user, assignment.course):
            flash('You do not have access to this assignment.', 'danger')
            return redirect(url_for('user_dashboard'))
        
        if not assignment.is_active:
            flash('This assignment is not currently available.', 'warning')
            return redirect(url_for('view_course', course_id=assignment.course_id))
        
        # Check if assignment has questions
        question_count = assignment.questions.count()
        if question_count == 0:
            flash('This assessment is not yet ready. Questions are still being prepared.', 'warning')
            return redirect(url_for('view_course', course_id=assignment.course_id))
        
        attempts = assignment.get_user_attempts(current_user.id)
        if assignment.max_attempts > 0 and len(attempts) >= assignment.max_attempts:
            flash('You have reached the maximum number of attempts for this assignment.', 'warning')
            return redirect(url_for('view_course', course_id=assignment.course_id))
        
        attempt = UserAssignmentAttempt(
            user_id=current_user.id,
            assignment_id=assignment_id
        )
        db.session.add(attempt)
        db.session.commit()
        
        return redirect(url_for('take_assignment', attempt_id=attempt.id))
    
    @app.route('/attempts/<int:attempt_id>', methods=['GET', 'POST'])
    @login_required
    def take_assignment(attempt_id):
        attempt = UserAssignmentAttempt.query.get_or_404(attempt_id)
        if attempt.user_id != current_user.id:
            abort(403)
        if attempt.completed_at:
            return redirect(url_for('assignment_result', attempt_id=attempt.id))
        
        assignment = attempt.assignment
        questions = Question.query.filter_by(assignment_id=assignment.id).order_by(Question.order).all()
        
        # Initialize answers and question order if not already done
        answers = json.loads(attempt.answers) if attempt.answers else {}
        
        # We store the question order in the session for this attempt
        session_key = f'assignment_order_{attempt.id}'
        if session_key not in session:
            q_ids = [q.id for q in questions]
            if assignment.shuffle_questions:
                import random
                random.shuffle(q_ids)
            session[session_key] = q_ids
        
        ordered_q_ids = session[session_key]
        
        # Get current question index from URL
        q_idx = request.args.get('q', 0, type=int)
        if q_idx < 0: q_idx = 0
        if q_idx >= len(ordered_q_ids):
            q_idx = len(ordered_q_ids) - 1
            
        current_q_id = ordered_q_ids[q_idx]
        current_question = next((q for q in questions if q.id == current_q_id), None)
        
        if not current_question:
            flash('Question not found.', 'danger')
            return redirect(url_for('view_course', course_id=assignment.course_id))

        if request.method == 'POST':
            answer = request.form.get(f'question_{current_q_id}')
            if answer:
                answers[str(current_q_id)] = answer
                attempt.answers = json.dumps(answers)
                db.session.commit()
            
            # Navigate to next question or result
            next_idx = q_idx + 1
            if next_idx < len(ordered_q_ids):
                return redirect(url_for('take_assignment', attempt_id=attempt.id, q=next_idx))
            else:
                # Calculate final score and complete attempt
                total_points = 0
                earned_points = 0
                for q in questions:
                    q_points = q.points or 1
                    total_points += q_points
                    user_ans = answers.get(str(q.id))
                    if user_ans and q.is_correct(user_ans):
                        earned_points += q_points
                
                score = round((earned_points / total_points * 100) if total_points > 0 else 0)
                attempt.score = score
                attempt.completed_at = datetime.utcnow()
                db.session.commit()
                session.pop(session_key, None)
                return redirect(url_for('assignment_result', attempt_id=attempt.id))

        return render_template('user/take_assignment.html',
                               title=assignment.title,
                               assignment=assignment,
                               attempt=attempt,
                               question=current_question,
                               q_idx=q_idx,
                               total_q=len(ordered_q_ids),
                               user_answer=answers.get(str(current_q_id)))
    
    @app.route('/attempts/<int:attempt_id>/result')
    @login_required
    def assignment_result(attempt_id):
        attempt = UserAssignmentAttempt.query.get_or_404(attempt_id)
        
        if attempt.user_id != current_user.id and not current_user.is_admin:
            abort(403)
        
        if not attempt.completed_at:
            return redirect(url_for('take_assignment', attempt_id=attempt.id))
        
        assignment = attempt.assignment
        questions = Question.query.filter_by(assignment_id=assignment.id).order_by(Question.order).all()
        
        answers = json.loads(attempt.answers) if attempt.answers else {}
        
        question_results = []
        for question in questions:
            user_answer = answers.get(str(question.id))
            is_correct = question.is_correct(user_answer) if user_answer else False
            
            question_results.append({
                'question': question,
                'user_answer': user_answer,
                'is_correct': is_correct
            })
        
        return render_template('user/assignment_result.html',
                               title=f'{assignment.title} - Results',
                               assignment=assignment,
                               attempt=attempt,
                               question_results=question_results)

    @app.route('/courses/<int:course_id>/certificate')
    @login_required
    def download_certificate(course_id):
        course = Course.query.get_or_404(course_id)
        if not has_user_completed_course(current_user.id, course.id):
            flash('You must complete all lessons and pass the assignment to get a certificate.', 'warning')
            return redirect(url_for('view_course', course_id=course_id))
        
        if not course.issue_certificates:
            flash('Certificates are not enabled for this course.', 'info')
            return redirect(url_for('view_course', course_id=course_id))

        from reportlab.pdfgen import canvas
        from reportlab.lib.pagesizes import letter
        import io
        from flask import send_file
        
        buffer = io.BytesIO()
        p = canvas.Canvas(buffer, pagesize=letter)
        width, height = letter
        
        p.setStrokeColorRGB(0.1, 0.2, 0.4)
        p.setLineWidth(5)
        p.rect(50, 50, width-100, height-100)
        
        p.setFont("Helvetica-Bold", 35)
        p.drawCentredString(width/2.0, height - 150, "Certificate of Completion")
        p.setFont("Helvetica", 20)
        p.drawCentredString(width/2.0, height - 250, "This is to certify that")
        p.setFont("Helvetica-Bold", 30)
        p.drawCentredString(width/2.0, height - 300, current_user.username)
        p.setFont("Helvetica", 20)
        p.drawCentredString(width/2.0, height - 350, "has successfully completed the course")
        p.setFont("Helvetica-Bold", 25)
        p.drawCentredString(width/2.0, height - 400, course.title)
        p.setFont("Helvetica", 15)
        p.drawCentredString(width/2.0, height - 550, f"Issued on {datetime.utcnow().strftime('%B %d, %Y')}")
        p.drawCentredString(width/2.0, height - 580, "Erlang Systems LMS")
        
        p.showPage()
        p.save()
        buffer.seek(0)
        
        pdf_data = buffer.getvalue()
        
        try:
            from .utils.email_helpers import send_certificate_email
            send_certificate_email(
                to_email=current_user.email,
                username=current_user.username,
                course_title=course.title,
                pdf_content=pdf_data
            )
            flash('Certificate has been sent to your email and is ready for download.', 'success')
        except Exception as e:
            flash('Certificate generated for download (email could not be sent).', 'info')
        
        buffer.seek(0)
        return send_file(buffer, as_attachment=True, download_name=f"certificate_{course.id}.pdf", mimetype='application/pdf')

def check_and_send_mandatory_course_reminders():
    """Check for mandatory courses with 7 days or less remaining and send reminder emails"""
    from .utils.email_helpers import send_mandatory_course_reminder_email
    from sqlalchemy import and_
    
    reminders_sent = 0
    now = datetime.utcnow()
    seven_days_from_now = now + timedelta(days=7)
    
    mandatory_courses = MandatoryCourse.query.filter(
        and_(
            MandatoryCourse.deadline != None,
            MandatoryCourse.deadline > now,
            MandatoryCourse.deadline <= seven_days_from_now
        )
    ).all()
    
    for mc in mandatory_courses:
        if mc.user_id:
            users = [User.query.get(mc.user_id)]
        else:
            users = User.query.filter_by(is_admin=False, is_approved=True).all()
        
        course = Course.query.get(mc.course_id)
        if not course:
            continue
        
        for user in users:
            if not user:
                continue
            
            existing_reminder = MandatoryCourseReminder.query.filter_by(
                mandatory_course_id=mc.id,
                user_id=user.id,
                reminder_type='7_day'
            ).first()
            
            if existing_reminder:
                continue
            
            user_completed = has_user_completed_course(user.id, mc.course_id)
            if user_completed:
                continue
            
            days_remaining = (mc.deadline - now).days
            
            if send_mandatory_course_reminder_email(
                user.email,
                user.username,
                course.title,
                days_remaining,
                mc.deadline
            ):
                reminder = MandatoryCourseReminder(
                    mandatory_course_id=mc.id,
                    user_id=user.id,
                    reminder_type='7_day'
                )
                db.session.add(reminder)
                db.session.commit()
                reminders_sent += 1
    
    return reminders_sent


def has_user_completed_course(user_id, course_id):
    """Check if a user has completed a course (all lessons + passed assignment if required)"""
    course = Course.query.get(course_id)
    if not course:
        return False
    
    lessons = Lesson.query.filter_by(course_id=course_id).all()
    if not lessons:
        return True
    
    completed_lessons = 0
    for lesson in lessons:
        progress = UserLessonProgress.query.filter_by(
            user_id=user_id,
            lesson_id=lesson.id
        ).first()
        if progress and progress.status == 'completed':
            completed_lessons += 1
    
    lessons_completed = (completed_lessons == len(lessons))
    
    assignments = Assignment.query.filter_by(course_id=course_id, is_active=True).all()
    if not assignments:
        return lessons_completed
    
    for assignment in assignments:
        if assignment.user_has_passed(user_id):
            return True
    
    return False