import os
import pyotp
import qrcode
import base64
import io
from flask import current_app
from datetime import datetime
from app import db
from app.models import User, Interest, Course, UserInterest, CourseInterest, UserCourse

def generate_otp_secret():
    """Generate a new OTP secret for user 2FA setup"""
    return pyotp.random_base32()

def get_totp_uri(username, secret, issuer_name="AI Learning Platform"):
    """Generate the TOTP URI for QR code generation
    
    Creates a TOTP object with standard 30-second period
    """
    # Create TOTP object with standard settings
    # This uses SHA1 algorithm (default) and 30-second time period
    totp = pyotp.totp.TOTP(secret)
    
    # Generate the provisioning URI (for QR code)
    return totp.provisioning_uri(
        name=username, 
        issuer_name=issuer_name
    )

def generate_qr_code(username, secret):
    """Generate QR code for 2FA setup with optimized settings"""
    uri = get_totp_uri(username, secret)
    
    # Use smaller QR code settings for faster generation
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=6,  # Smaller box size
        border=2,    # Smaller border
    )
    qr.add_data(uri)
    qr.make(fit=True)
    
    # Use PIL/Pillow for image creation
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Save QR code to bytes
    buffered = io.BytesIO()
    img.save(buffered, format="PNG", optimize=True, compress_level=9)
    img_str = base64.b64encode(buffered.getvalue()).decode()
    return f"data:image/png;base64,{img_str}"

def verify_totp(secret, token):
    """Verify the provided TOTP token with an extended validation window
    
    This uses a window of +/- 1 time step (30 seconds before and after)
    to account for time differences between the server and the authenticator app
    """
    totp = pyotp.TOTP(secret)
    # Use a window of 1 which means 1 step before and after (total of 3 steps)
    # This represents a 90-second window (30 seconds per step)
    return totp.verify(token, valid_window=1)

def get_user_accessible_courses(user):
    """Get courses that are accessible to a user based on their interests"""
    if user.is_admin:
        return Course.query.all()
    
    # Get user interests with granted access
    user_interests = UserInterest.query.filter_by(
        user_id=user.id, 
        access_granted=True
    ).all()
    interest_ids = [ui.interest_id for ui in user_interests]
    
    if not interest_ids:
        return []
    
    # Find courses related to user's interests
    course_interests = CourseInterest.query.filter(
        CourseInterest.interest_id.in_(interest_ids)
    ).all()
    course_ids = [ci.course_id for ci in course_interests]
    
    # Get unique course IDs
    course_ids = list(set(course_ids))
    
    if not course_ids:
        return []
    
    # Fetch the courses
    courses = Course.query.filter(Course.id.in_(course_ids)).all()
    return courses

def user_can_access_course(user, course):
    """Check if a user has access to a specific course"""
    if user.is_admin:
        return True
    
    # Check if user is directly enrolled in the course
    enrolled = UserCourse.query.filter_by(
        user_id=user.id,
        course_id=course.id
    ).first()
    if enrolled:
        return True
    
    # Check if the user has access through interests
    user_interests = UserInterest.query.filter_by(
        user_id=user.id, 
        access_granted=True
    ).all()
    user_interest_ids = [ui.interest_id for ui in user_interests]
    
    course_interests = CourseInterest.query.filter_by(course_id=course.id).all()
    course_interest_ids = [ci.interest_id for ci in course_interests]
    
    # Check if any of the user's interests match the course's interests
    for interest_id in user_interest_ids:
        if interest_id in course_interest_ids:
            return True
    
    return False

def get_pending_users():
    """Get users waiting for admin approval"""
    return User.query.filter_by(is_approved=False).all()

def approve_user(user_id, admin_id):
    """Approve a pending user registration"""
    try:
        print(f"Approving user_id: {user_id} by admin_id: {admin_id}")
        user = User.query.get(user_id)
        admin = User.query.get(admin_id)
        
        if not user or not admin or not admin.is_admin:
            print(f"Invalid user ({user}) or admin ({admin})")
            return False
        
        if user and not user.is_approved:
            user.is_approved = True
            db.session.commit()
            print(f"Successfully approved user: {user.username}")
            return True
        print(f"User {user.username if user else 'None'} already approved or not found")
        return False
    except Exception as e:
        print(f"Error approving user: {e}")
        db.session.rollback()
        return False

def reject_user(user_id):
    """Reject and delete a pending user registration"""
    try:
        print(f"Rejecting user_id: {user_id}")
        user = User.query.get(user_id)
        
        if not user:
            print("User not found")
            return False
        
        if user and not user.is_approved:
            # First delete any related user interests to avoid constraint errors
            UserInterest.query.filter_by(user_id=user.id).delete()
            
            # Now delete the user
            db.session.delete(user)
            db.session.commit()
            print(f"Successfully rejected user: {user.username}")
            return True
        
        print(f"User {user.username if user else 'None'} already approved or not found")
        return False
    except Exception as e:
        print(f"Error rejecting user: {e}")
        db.session.rollback()
        return False

def grant_interest_access(user_id, interest_id, admin_id):
    """Grant a user access to content related to an interest"""
    user_interest = UserInterest.query.filter_by(
        user_id=user_id,
        interest_id=interest_id
    ).first()
    
    if not user_interest:
        user_interest = UserInterest(
            user_id=user_id,
            interest_id=interest_id
        )
        db.session.add(user_interest)
    
    user_interest.access_granted = True
    user_interest.granted_at = datetime.utcnow()
    user_interest.granted_by = admin_id
    db.session.commit()
    return True

def revoke_interest_access(user_id, interest_id):
    """Revoke a user's access to content related to an interest"""
    user_interest = UserInterest.query.filter_by(
        user_id=user_id,
        interest_id=interest_id
    ).first()
    
    if user_interest:
        user_interest.access_granted = False
        user_interest.granted_at = None
        user_interest.granted_by = None
        db.session.commit()
        return True
    return False

def get_user_interests_status(user_id):
    """Get all interests and whether a user has selected them and has access"""
    all_interests = Interest.query.all()
    user_interests = UserInterest.query.filter_by(user_id=user_id).all()
    
    user_interest_map = {ui.interest_id: ui.access_granted for ui in user_interests}
    
    result = []
    for interest in all_interests:
        selected = interest.id in user_interest_map
        access_granted = user_interest_map.get(interest.id, False)
        result.append({
            'interest': interest,
            'selected': selected,
            'access_granted': access_granted
        })
    
    return result

def get_recommended_courses(user, max_courses=3):
    """Get course recommendations for a user based on their interests
    
    This function returns courses that:
    1. The user has access to through their interests, but hasn't enrolled in yet
    2. Related to the user's interests, sorted by relevance
    """
    if user.is_admin:
        # For admins, recommend all courses they're not enrolled in
        enrolled_course_ids = [uc.course_id for uc in UserCourse.query.filter_by(user_id=user.id).all()]
        return Course.query.filter(~Course.id.in_(enrolled_course_ids) if enrolled_course_ids else True).limit(max_courses).all()
    
    # Get user interests with granted access
    user_interests = UserInterest.query.filter_by(
        user_id=user.id, 
        access_granted=True
    ).all()
    interest_ids = [ui.interest_id for ui in user_interests]
    
    if not interest_ids:
        return []
    
    # Get courses the user is already enrolled in
    enrolled_course_ids = [uc.course_id for uc in UserCourse.query.filter_by(user_id=user.id).all()]
    
    # Find courses related to user's interests that they're not enrolled in yet
    course_interests = CourseInterest.query.filter(
        CourseInterest.interest_id.in_(interest_ids)
    ).all()
    
    # Group course IDs by how many of the user's interests they match (for relevance scoring)
    course_relevance = {}
    for ci in course_interests:
        if ci.course_id not in enrolled_course_ids:
            course_relevance[ci.course_id] = course_relevance.get(ci.course_id, 0) + 1
    
    # Sort course IDs by relevance score (descending)
    sorted_course_ids = sorted(course_relevance.keys(), key=lambda x: course_relevance[x], reverse=True)
    
    # Limit to maximum number of recommendations
    sorted_course_ids = sorted_course_ids[:max_courses]
    
    if not sorted_course_ids:
        return []
    
    # Fetch the courses in order of relevance
    courses = []
    for course_id in sorted_course_ids:
        course = Course.query.get(course_id)
        if course:
            courses.append(course)
    
    return courses

def setup_initial_data():
    """Set up initial data if database is empty"""
    try:
        # Check if there's any admin user
        # First, make sure tables exist
        with db.engine.connect() as connection:
            # Check if users table exists
            if not connection.dialect.has_table(connection, 'users'):
                # If no tables exist yet, return early - they'll be created by db.create_all()
                print("Tables don't exist yet, skipping initial data setup")
                return
                
        admin = User.query.filter_by(is_admin=True).first()
        if not admin:
            # Create admin user (special case - bypass 2FA for admin)
            admin = User(
                username='admin',
                email='admin@example.com',
                is_admin=True,
                is_approved=True,
                is_2fa_enabled=False  # Admin doesn't need 2FA
            )
            admin.set_password('Admin123')
            db.session.add(admin)
            db.session.commit()
            print("Admin user created successfully without 2FA")
            
            # Create some interests
            interests = [
                {'name': 'Machine Learning', 'description': 'Learn about algorithms that can learn from data'},
                {'name': 'Deep Learning', 'description': 'Neural networks and deep architectures'},
                {'name': 'Natural Language Processing', 'description': 'Processing and understanding human language'},
                {'name': 'Computer Vision', 'description': 'Enabling machines to see and interpret visual data'},
                {'name': 'Reinforcement Learning', 'description': 'Training agents to make decisions through rewards'}
            ]
            
            for interest_data in interests:
                interest = Interest(
                    name=interest_data['name'],
                    description=interest_data['description'],
                    created_by=admin.id
                )
                db.session.add(interest)
            
            db.session.commit()
            
            # Commit the interests first to ensure they're all created
            db.session.commit()
            print("Created interests")
            
            # Create some courses
            ml_interest = Interest.query.filter_by(name='Machine Learning').first()
            dl_interest = Interest.query.filter_by(name='Deep Learning').first()
            nlp_interest = Interest.query.filter_by(name='Natural Language Processing').first()
            
            if ml_interest and dl_interest and nlp_interest:
                from app.models import Course, CourseInterest, Lesson
                
                courses = [
                    {
                        'title': 'Introduction to Machine Learning',
                        'description': 'Learn the basics of machine learning algorithms and techniques.',
                        'interests': [ml_interest],
                        'lessons': [
                            {'title': 'What is Machine Learning?', 'content': 'Machine learning is a field of study that gives computers the ability to learn without being explicitly programmed.', 'order': 1},
                            {'title': 'Supervised Learning', 'content': 'Supervised learning is a type of machine learning where the model is trained on labeled data.', 'order': 2},
                            {'title': 'Unsupervised Learning', 'content': 'Unsupervised learning is a type of machine learning where the model is trained on unlabeled data.', 'order': 3}
                        ]
                    },
                    {
                        'title': 'Deep Learning Fundamentals',
                        'description': 'Explore neural networks and deep learning architectures.',
                        'interests': [dl_interest],
                        'lessons': [
                            {'title': 'Neural Networks Basics', 'content': 'A neural network is a series of algorithms that endeavors to recognize underlying relationships in a set of data.', 'order': 1},
                            {'title': 'Activation Functions', 'content': 'Activation functions determine the output of a neural network model and whether a neuron will be activated or not.', 'order': 2},
                            {'title': 'Backpropagation', 'content': 'Backpropagation is an algorithm used to train neural networks by adjusting the weights based on the error rate.', 'order': 3}
                        ]
                    },
                    {
                        'title': 'Natural Language Processing with Python',
                        'description': 'Learn to process and analyze text data using Python.',
                        'interests': [nlp_interest, ml_interest],
                        'lessons': [
                            {'title': 'Text Preprocessing', 'content': 'Text preprocessing involves cleaning and transforming text data to make it suitable for analysis.', 'order': 1},
                            {'title': 'Word Embeddings', 'content': 'Word embeddings are a type of word representation that allows words with similar meaning to have similar representation.', 'order': 2},
                            {'title': 'Sentiment Analysis', 'content': 'Sentiment analysis is the process of determining the emotional tone behind a series of words.', 'order': 3}
                        ]
                    }
                ]
                
                for course_data in courses:
                    # Check if course already exists
                    existing_course = Course.query.filter_by(title=course_data['title']).first()
                    if not existing_course:
                        course = Course(
                            title=course_data['title'],
                            description=course_data['description'],
                            created_by=admin.id
                        )
                        db.session.add(course)
                        db.session.flush()  # Get the course ID
                        
                        # Add course-interest relationships
                        for interest in course_data['interests']:
                            course_interest = CourseInterest(
                                course_id=course.id,
                                interest_id=interest.id,
                                created_by=admin.id
                            )
                            db.session.add(course_interest)
                        
                        # Add lessons
                        for lesson_data in course_data['lessons']:
                            lesson = Lesson(
                                title=lesson_data['title'],
                                content=lesson_data['content'],
                                course_id=course.id,
                                order=lesson_data['order']
                            )
                            db.session.add(lesson)
                
                db.session.commit()
                print("Created courses and lessons")
            else:
                print("Could not find required interests to create courses")
            print("Created initial interests, courses, and lessons")
    except Exception as e:
        print(f"Error in setup_initial_data: {e}")
        db.session.rollback()
