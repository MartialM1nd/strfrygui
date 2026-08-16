from functools import wraps
from flask import flash, jsonify, redirect, request, url_for
from flask_login import current_user, logout_user
from config import Security


def wants_json_response():
    """Return whether the caller explicitly expects a JSON response."""
    return (
        request.path.startswith('/api/')
        or request.accept_mimetypes['application/json']
        > request.accept_mimetypes['text/html']
    )


def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                if wants_json_response():
                    return jsonify({'error': 'Authentication required.'}), 401
                return redirect(url_for('login'))

            if not current_user.is_active:
                logout_user()
                if wants_json_response():
                    return jsonify({'error': 'Authentication required.'}), 401
                flash('Your account has been deactivated.', 'danger')
                return redirect(url_for('login'))
            
            if current_user.role not in roles:
                if wants_json_response():
                    return jsonify({'error': 'Permission denied.'}), 403
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
                if wants_json_response():
                    return jsonify({'error': 'Authentication required.'}), 401
                return redirect(url_for('login'))

            if not current_user.is_active:
                logout_user()
                if wants_json_response():
                    return jsonify({'error': 'Authentication required.'}), 401
                flash('Your account has been deactivated.', 'danger')
                return redirect(url_for('login'))
            
            if not Security.has_permission(current_user.role, permission):
                if wants_json_response():
                    return jsonify({'error': 'Permission denied.'}), 403
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
