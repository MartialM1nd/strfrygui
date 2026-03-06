from functools import wraps
from flask import abort, redirect, url_for, flash
from flask_login import current_user
from config import Security


def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('login'))
            
            if current_user.role not in roles:
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('index'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('login'))
            
            if not Security.has_permission(current_user.role, permission):
                flash('You do not have permission to perform this action.', 'danger')
                return redirect(url_for('index'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def admin_required(f):
    return role_required('admin')(f)


def moderator_required(f):
    return role_required('admin', 'moderator')(f)


def viewer_or_higher(f):
    return role_required('admin', 'moderator', 'viewer')(f)
