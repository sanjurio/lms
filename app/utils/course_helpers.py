from ..models import (
    User,
    Course,
    Interest,
    UserInterest,
    UserCourse,
    CourseInterest,
    MandatoryCourse
)

def get_user_accessible_courses(user):
    """Get courses accessible to a user based on their interests, approval status, and mandatory assignments"""
    if not user.is_approved:
        return []

    accessible_course_ids = set()

    # Get user's approved interests
    approved_interests = UserInterest.query.filter_by(
        user_id=user.id,
        access_granted=True
    ).all()

    # Get courses for approved interests
    if approved_interests:
        interest_ids = [ui.interest_id for ui in approved_interests]
        course_interests = CourseInterest.query.filter(
            CourseInterest.interest_id.in_(interest_ids)
        ).all()
        accessible_course_ids.update(ci.course_id for ci in course_interests)

    # Get mandatory courses for this user (global + user-specific)
    mandatory_courses = MandatoryCourse.get_user_mandatory_courses(user.id)
    for mc in mandatory_courses:
        accessible_course_ids.add(mc.course_id)

    if not accessible_course_ids:
        return []

    courses = Course.query.filter(
        Course.id.in_(accessible_course_ids)
    ).all()

    return [
        course for course in courses
        if user_can_access_course(user, course)
    ]


def get_recommended_courses(user):
    """Get recommended courses based on user interests"""
    if not user.is_approved:
        return []

    return get_user_accessible_courses(user)[:3]


def user_can_access_course(user, course):
    """Check if user can access a specific course"""
    if not user.is_approved:
        return False

    if user.is_admin:
        return True

    # ---- SAFE ACCESS LEVEL COMPARISON (FIX) ----
    try:
        user_level = int(user.access_level)
    except (TypeError, ValueError):
        user_level = 1  # fallback D1

    try:
        course_level = int(course.required_level)
    except (TypeError, ValueError):
        course_level = 1

    if user_level < course_level:
        return False
    # -------------------------------------------

    # Domain restriction (THBS-only courses)
    if course.is_thbs_restricted():
        if user.email_domain != 'thbs.com':
            return False

    # Mandatory courses bypass interests
    if MandatoryCourse.is_mandatory_for_user(course.id, user.id):
        return True

    # Interest-based access
    user_interests = UserInterest.query.filter_by(
        user_id=user.id,
        access_granted=True
    ).all()

    interest_ids = {ui.interest_id for ui in user_interests}

    course_interests = CourseInterest.query.filter_by(
        course_id=course.id
    ).all()

    course_interest_ids = {ci.interest_id for ci in course_interests}

    return bool(interest_ids & course_interest_ids)


def get_user_interests_status(user_id):
    """Get ALL interests with their access status for a specific user"""
    from ..models import UserInterest, Interest

    all_interests = Interest.query.all()
    user_interests = UserInterest.query.filter_by(user_id=user_id).all()

    user_interest_map = {
        ui.interest_id: ui for ui in user_interests
    }

    result = []
    for interest in all_interests:
        user_interest = user_interest_map.get(interest.id)
        result.append({
            'interest': interest,
            'access_granted': user_interest.access_granted if user_interest else False,
            'selected': user_interest is not None
        })

    return result
