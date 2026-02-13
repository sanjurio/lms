#!/usr/bin/env python3
"""
Create test courses to demonstrate domain-specific access control
"""
import os
from app import create_app
from app.models import db, User, Course, Interest, CourseInterest

def create_test_courses():
    """Create test courses including THBS-restricted ones"""
    app = create_app()
    
    with app.app_context():
        # Find or create an admin user
        admin = User.query.filter_by(is_admin=True).first()
        if not admin:
            print("No admin user found. Please run create_admin_user.py first")
            return
        
        # Find or create Erlang interest
        erlang_interest = Interest.query.filter_by(name='Erlang/OTP').first()
        if not erlang_interest:
            erlang_interest = Interest(
                name='Erlang/OTP',
                description='Erlang programming language and OTP framework',
                created_by=admin.id
            )
            db.session.add(erlang_interest)
            db.session.commit()
        
        # Create regular Erlang course
        regular_course = Course(
            title='Erlang Basics and Fundamentals',
            description='Learn the fundamentals of Erlang programming language. This course covers basic syntax, pattern matching, and concurrent programming concepts.',
            created_by=admin.id
        )
        db.session.add(regular_course)
        
        # Create THBS-restricted course (contains erlang-l3)
        thbs_course = Course(
            title='Advanced Erlang-L3 System Architecture',
            description='Advanced Erlang-L3 course covering enterprise-level system design, distributed architectures, and performance optimization. Restricted to THBS domain users only.',
            created_by=admin.id
        )
        db.session.add(thbs_course)
        
        # Create another THBS-restricted course
        thbs_course2 = Course(
            title='Erlang-L3 Production Deployment Strategies',
            description='Learn how to deploy Erlang-L3 systems in production environments. Covers monitoring, scaling, and maintenance strategies for enterprise applications.',
            created_by=admin.id
        )
        db.session.add(thbs_course2)
        
        # Create a course with erlang-l3 in different case
        thbs_course3 = Course(
            title='Enterprise ERLANG-L3 Best Practices',
            description='Best practices for ERLANG-L3 development in enterprise environments. This course is designed for senior developers working on large-scale systems.',
            created_by=admin.id
        )
        db.session.add(thbs_course3)
        
        db.session.commit()
        
        # Link courses to interests
        courses = [regular_course, thbs_course, thbs_course2, thbs_course3]
        for course in courses:
            course_interest = CourseInterest(
                course_id=course.id,
                interest_id=erlang_interest.id,
                created_by=admin.id
            )
            db.session.add(course_interest)
        
        db.session.commit()
        
        print(f"✓ Created {len(courses)} test courses:")
        print(f"  - Regular course: {regular_course.title}")
        print(f"  - THBS-restricted courses:")
        for course in [thbs_course, thbs_course2, thbs_course3]:
            print(f"    * {course.title} (is_thbs_restricted: {course.is_thbs_restricted()})")
        
        print("\nDomain access control rules:")
        print("  - THBS domain users (@thbs.com): Can access ALL courses")
        print("  - BT domain users (@bt.com): Cannot access erlang-l3 courses")
        print("  - Other domains: Standard interest-based access")

if __name__ == '__main__':
    create_test_courses()