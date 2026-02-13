import os
from datetime import datetime, timedelta
from main import app
from app.models import db, User, Interest, Course, Lesson, UserInterest, CourseInterest, UserLessonProgress, ForumTopic, ForumReply, UserActivity, MandatoryCourse, Assignment, Question

def populate():
    with app.app_context():
        print("Populating dummy data...")
        
        # 1. Teams (Interests)
        teams = [
            ("Engineering", "Core engineering team focusing on product development."),
            ("Marketing", "Promoting products and managing brand identity."),
            ("Sales", "Driving revenue and customer acquisition."),
            ("HR", "Human resources and talent management."),
            ("Operations", "Daily business operations and logistics."),
            ("Customer Support", "Assisting customers with technical issues.")
        ]
        
        team_objs = []
        for name, desc in teams:
            team = Interest.query.filter_by(name=name).first()
            if not team:
                team = Interest(name=name, description=desc)
                db.session.add(team)
            team_objs.append(team)
        db.session.commit()
        
        # 2. Users
        admin = User.query.filter_by(email="admin@example.com").first()
        if not admin:
            admin = User(username="admin", email="admin@example.com", is_admin=True, is_approved=True)
            admin.set_password("Admin123")
            db.session.add(admin)
        
        users_data = [
            ("john_doe", "john@thbs.com", "User123!", "thbs.com", 1, True),
            ("jane_smith", "jane@bt.com", "User123!", "bt.com", 2, True),
        ]
        
        user_objs = []
        for uname, email, pwd, domain, level, approved in users_data:
            user = User.query.filter_by(email=email).first()
            if not user:
                user = User(username=uname, email=email, is_approved=approved, access_level=level, email_domain=domain)
                user.set_password(pwd)
                db.session.add(user)
            user_objs.append(user)
        db.session.commit()
        
        # 4. Courses
        courses_data = [
            ("Introduction to Erlang", "Learn the basics of Erlang programming language.", 1, "Engineering", "/static/images/courses/erlang.png"),
            ("Marketing Basics", "Foundations of modern marketing.", 1, "Marketing", "/static/images/courses/marketing.png"),
            ("Sales Strategy 2026", "Advanced sales techniques for the current year.", 2, "Sales", "/static/images/courses/sales.png")
        ]
        
        youtube_links = [
            "https://www.youtube.com/embed/uKfKtXYLG78",
            "https://www.youtube.com/embed/ZiaDrBmi32M",
            "https://www.youtube.com/embed/lZKP0Z0A7I0"
        ]
        
        course_objs = []
        for i, (title, desc, level, team_name, img_url) in enumerate(courses_data):
            course = Course.query.filter_by(title=title).first()
            if not course:
                course = Course(title=title, description=desc, required_level=level, created_by=admin.id, cover_image_url=img_url)
                db.session.add(course)
                db.session.flush()
                
                team = Interest.query.filter_by(name=team_name).first()
                if team:
                    ci = CourseInterest(course_id=course.id, interest_id=team.id)
                    db.session.add(ci)
            course_objs.append(course)
        db.session.commit()
        
        # 5. Lessons
        for idx, course in enumerate(course_objs):
            for i in range(1, 4):
                lesson = Lesson.query.filter_by(course_id=course.id, order=i).first()
                if not lesson:
                    lesson = Lesson(
                        title=f"Lesson {i} of {course.title}",
                        content=f"Detailed content for lesson {i} in '{course.title}'.",
                        content_type='video' if i == 1 else 'text',
                        video_url=youtube_links[idx % len(youtube_links)] if i == 1 else None,
                        course_id=course.id,
                        order=i
                    )
                    db.session.add(lesson)
        db.session.commit()
        
        print("Dummy data populated successfully!")

if __name__ == "__main__":
    populate()
