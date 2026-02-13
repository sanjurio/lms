from ..models import User, UserInterest
from .. import db

def get_pending_users():
    """Get users pending approval"""
    return User.query.filter_by(is_approved=False, is_admin=False).all()

def approve_user(user_id, approved_by_id=None):
    """Approve a user"""
    user = User.query.get(user_id)
    if user:
        user.is_approved = True
        db.session.commit()
        return True
    return False

def reject_user(user_id, rejected_by_id=None):
    """Reject a user (delete their account)"""
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        return True
    return False

def set_user_video_access(user_id, video_access):
    """Set video access for user (force override domain settings)"""
    user = User.query.get(user_id)
    if user:
        # Instead of resetting the whole access_level string,
        # we check the hierarchical D level and keep it.
        # If video_access is True (INTERNAL), we ensure they have full access.
        # This function might need further refinement based on how 'full_access' 
        # relates to D1-D4, but for now we stop it from resetting D levels if possible.
        # However, the user specifically mentioned it resets to D1.
        
        # Let's just make sure we don't change access_level if it's already an integer (D1-D4)
        if isinstance(user.access_level, str):
            if video_access:
                user.access_level = 'full_access'
            else:
                user.access_level = 'text_only'
        # If it's an integer, we leave it alone or handle it hierarchically.
        # The user said: "When a admin approves the user their D level resets to D1"
        # This was likely happening in approve_user which I already fixed in routes.py
        
        db.session.commit()
        return True
    return False

def grant_interest_access(user_id, interest_id):
    """Grant a user access to content related to an interest"""
    from flask_login import current_user
    from datetime import datetime
    import logging
    
    logger = logging.getLogger(__name__)
    
    try:
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
        user_interest.granted_by = current_user.id
        
        db.session.commit()
        logger.info(f"Granted interest {interest_id} access to user {user_id}")
        return True
    except Exception as e:
        logger.error(f"Error granting interest access: {str(e)}")
        db.session.rollback()
        return False

def revoke_interest_access(user_id, interest_id):
    """Revoke user access to an interest"""
    import logging
    
    logger = logging.getLogger(__name__)
    
    try:
        user_interest = UserInterest.query.filter_by(
            user_id=user_id, 
            interest_id=interest_id
        ).first()

        if user_interest:
            user_interest.access_granted = False
            db.session.commit()
            logger.info(f"Revoked interest {interest_id} access from user {user_id}")
            return True
        return False
    except Exception as e:
        logger.error(f"Error revoking interest access: {str(e)}")
        db.session.rollback()
        return False