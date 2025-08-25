from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import os
import json
import uuid
import time
import csv
import io
import requests
from threading import Thread
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import base64

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production-' + str(uuid.uuid4()))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///wordpress_manager.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=30)

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# In-memory storage for processing sessions
processing_sessions = {}

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    websites = db.relationship('Website', backref='user', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Website(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    website_name = db.Column(db.String(100), nullable=False)
    website_url = db.Column(db.String(255), nullable=False)
    wp_api_key = db.Column(db.Text, nullable=False)  # WordPress Application Password
    wp_username = db.Column(db.String(100), nullable=False)  # WordPress username
    description = db.Column(db.Text)
    service_account_key = db.Column(db.Text)  # Google Service Account JSON
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    indexing_logs = db.relationship('IndexingLog', backref='website', lazy=True, cascade='all, delete-orphan')

class IndexingLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    website_id = db.Column(db.Integer, db.ForeignKey('website.id'), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    action = db.Column(db.String(20), nullable=False)  # 'URL_UPDATED' or 'URL_DELETED'
    status = db.Column(db.String(20), nullable=False)  # 'success', 'error'
    response_message = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# WordPress API Helper Functions
class WordPressAPI:
    @staticmethod
    def test_connection(website_url, username, api_key):
        """Test WordPress API connection"""
        try:
            url = f"{website_url.rstrip('/')}/wp-json/wp/v2/posts?per_page=1"
            auth = (username, api_key)
            response = requests.get(url, auth=auth, timeout=10)
            return response.status_code == 200
        except Exception:
            return False

    @staticmethod
    def get_posts(website_url, username, api_key, per_page=10, page=1):
        """Get WordPress posts"""
        try:
            url = f"{website_url.rstrip('/')}/wp-json/wp/v2/posts"
            params = {'per_page': per_page, 'page': page}
            auth = (username, api_key)
            response = requests.get(url, auth=auth, params=params, timeout=30)
            if response.status_code == 200:
                return response.json()
            return None
        except Exception:
            return None

    @staticmethod
    def get_post_by_url(website_url, username, api_key, post_url):
        """Get a specific post by URL slug"""
        try:
            # Extract slug from URL
            slug = post_url.rstrip('/').split('/')[-1]
            url = f"{website_url.rstrip('/')}/wp-json/wp/v2/posts"
            params = {'slug': slug}
            auth = (username, api_key)
            response = requests.get(url, auth=auth, params=params, timeout=30)
            if response.status_code == 200:
                posts = response.json()
                return posts[0] if posts else None
            return None
        except Exception:
            return None

    @staticmethod
    def update_post(website_url, username, api_key, post_id, data):
        """Update a WordPress post"""
        try:
            url = f"{website_url.rstrip('/')}/wp-json/wp/v2/posts/{post_id}"
            auth = (username, api_key)
            headers = {'Content-Type': 'application/json'}
            response = requests.post(url, auth=auth, headers=headers, json=data, timeout=30)
            return response.status_code == 200, response.json()
        except Exception as e:
            return False, str(e)

    @staticmethod
    def get_yoast_data(post_data):
        """Extract Yoast SEO data from post"""
        yoast_data = {}
        if 'yoast_head_json' in post_data:
            yoast = post_data['yoast_head_json']
            yoast_data = {
                'title': yoast.get('title', ''),
                'description': yoast.get('description', ''),
                'og_title': yoast.get('og_title', ''),
                'og_description': yoast.get('og_description', ''),
                'twitter_title': yoast.get('twitter_title', ''),
                'twitter_description': yoast.get('twitter_description', ''),
            }
        return yoast_data

# Google Indexing API Helper Functions
class GoogleIndexingAPI:
    @staticmethod
    def submit_url(service_account_json, url, action_type='URL_UPDATED'):
        """Submit URL to Google Indexing API"""
        try:
            # Parse service account JSON
            service_account_info = json.loads(service_account_json)
            
            # Create credentials
            credentials = service_account.Credentials.from_service_account_info(
                service_account_info,
                scopes=['https://www.googleapis.com/auth/indexing']
            )
            
            # Build the service
            service = build('indexing', 'v3', credentials=credentials)
            
            # Submit the URL
            body = {
                'url': url,
                'type': action_type
            }
            
            result = service.urlNotifications().publish(body=body).execute()
            return True, result
            
        except HttpError as e:
            return False, f"HTTP Error: {e}"
        except Exception as e:
            return False, f"Error: {e}"

    @staticmethod
    def get_url_status(service_account_json, url):
        """Get URL status from Google Indexing API"""
        try:
            service_account_info = json.loads(service_account_json)
            credentials = service_account.Credentials.from_service_account_info(
                service_account_info,
                scopes=['https://www.googleapis.com/auth/indexing']
            )
            
            service = build('indexing', 'v3', credentials=credentials)
            result = service.urlNotifications().getMetadata(url=url).execute()
            return True, result
            
        except HttpError as e:
            return False, f"HTTP Error: {e}"
        except Exception as e:
            return False, f"Error: {e}"

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login')
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        # Get user statistics
        total_websites = Website.query.filter_by(user_id=current_user.id).count()
        total_indexing_requests = db.session.query(IndexingLog).join(Website).filter(Website.user_id == current_user.id).count()
        successful_indexing = db.session.query(IndexingLog).join(Website).filter(Website.user_id == current_user.id, IndexingLog.status == 'success').count()
        
        stats = {
            'total_websites': total_websites,
            'total_indexing_requests': total_indexing_requests,
            'successful_indexing': successful_indexing,
            'success_rate': round((successful_indexing / total_indexing_requests * 100) if total_indexing_requests > 0 else 0, 1)
        }
    except Exception as e:
        # Fallback stats if there's an error
        stats = {
            'total_websites': 0,
            'total_indexing_requests': 0,
            'successful_indexing': 0,
            'success_rate': 0
        }
        print(f"Error loading dashboard stats: {e}")
    
    return render_template('dashboard.html', stats=stats)

@app.route('/manage-websites')
@login_required
def manage_websites():
    websites = Website.query.filter_by(user_id=current_user.id).all()
    return render_template('manage_websites.html', websites=websites)

@app.route('/index-api')
@login_required
def index_api():
    websites = Website.query.filter_by(user_id=current_user.id).all()
    return render_template('index_api.html', websites=websites)

@app.route('/api-index-settings')
@login_required
def api_index_settings():
    websites = Website.query.filter_by(user_id=current_user.id).all()
    return render_template('api_index_settings.html', websites=websites)

@app.route('/single-page-editor')
@login_required
def single_page_editor():
    websites = Website.query.filter_by(user_id=current_user.id).all()
    return render_template('single_page_editor.html', websites=websites)

@app.route('/bulk-page-editor')
@login_required
def bulk_page_editor():
    websites = Website.query.filter_by(user_id=current_user.id).all()
    return render_template('bulk_page_editor.html', websites=websites)

@app.route('/user-profile')
@login_required
def user_profile():
    return render_template('user_profile.html')

# API Routes
@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '').strip()
        confirm_password = data.get('confirmPassword', '').strip()
        
        # Validation
        if not username or not email or not password:
            return jsonify({'success': False, 'message': 'All fields are required'}), 400
        
        if password != confirm_password:
            return jsonify({'success': False, 'message': 'Passwords do not match'}), 400
        
        if len(password) < 6:
            return jsonify({'success': False, 'message': 'Password must be at least 6 characters'}), 400
        
        # Check if user exists
        if User.query.filter_by(email=email).first():
            return jsonify({'success': False, 'message': 'Email already registered'}), 400
        
        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'message': 'Username already taken'}), 400
        
        # Create new user
        user = User(username=username, email=email)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Account created successfully'})
        
    except Exception as e:
        print(f"Registration error: {e}")
        return jsonify({'success': False, 'message': 'Registration failed'}), 500

@app.route('/api/login', methods=['POST'])
def api_login():
    try:
        data = request.get_json()
        login_input = data.get('email', '').strip().lower()  # Can be email or username
        password = data.get('password', '').strip()
        remember = data.get('remember', False)
        
        if not login_input or not password:
            return jsonify({'success': False, 'message': 'Email/Username and password are required'}), 400
        
        # Try to find user by email first, then by username
        user = User.query.filter_by(email=login_input).first()
        if not user:
            # If not found by email, try by username (case-insensitive)
            user = User.query.filter(db.func.lower(User.username) == login_input).first()
        
        if not user or not user.check_password(password):
            return jsonify({'success': False, 'message': 'Invalid email/username or password'}), 401
        
        # Login the user
        login_user(user, remember=remember)
        session.permanent = remember
        
        return jsonify({
            'success': True, 
            'message': 'Login successful',
            'user': {
                'username': user.username,
                'email': user.email
            }
        })
        
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({'success': False, 'message': 'Login failed'}), 500

@app.route('/api/logout', methods=['POST'])
@login_required
def api_logout():
    logout_user()
    return jsonify({'success': True, 'message': 'Logged out successfully'})

# CRITICAL FIX: Add the missing /api/user-profile route
@app.route('/api/user-profile')
@login_required
def api_user_profile():
    try:
        return jsonify({
            'username': current_user.username,
            'email': current_user.email,
            'member_since': current_user.created_at.strftime('%B %Y')
        })
    except Exception as e:
        print(f"Error loading user profile: {e}")
        return jsonify({'error': 'Failed to load user profile'}), 500

@app.route('/api/add-website', methods=['POST'])
@login_required
def add_website():
    try:
        data = request.get_json()
        website_name = data.get('website_name', '').strip()
        website_url = data.get('website_url', '').strip()
        wp_username = data.get('wp_username', '').strip()
        wp_api_key = data.get('wp_api_key', '').strip()
        description = data.get('description', '').strip()
        
        if not all([website_name, website_url, wp_username, wp_api_key]):
            return jsonify({'success': False, 'message': 'All required fields must be filled'}), 400
        
        # Ensure URL ends with /
        if not website_url.endswith('/'):
            website_url += '/'
        
        # Test WordPress API connection
        if not WordPressAPI.test_connection(website_url, wp_username, wp_api_key):
            return jsonify({'success': False, 'message': 'Failed to connect to WordPress API. Check credentials.'}), 400
        
        # Create new website
        website = Website(
            user_id=current_user.id,
            website_name=website_name,
            website_url=website_url,
            wp_username=wp_username,
            wp_api_key=wp_api_key,
            description=description
        )
        
        db.session.add(website)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Website added successfully', 'website_id': website.id})
        
    except Exception as e:
        print(f"Error adding website: {e}")
        return jsonify({'success': False, 'message': 'Failed to add website'}), 500

@app.route('/api/submit-indexing', methods=['POST'])
@login_required
def submit_indexing():
    try:
        data = request.get_json()
        website_id = data.get('website_id')
        url = data.get('url')
        action = data.get('action', 'URL_UPDATED')
        
        if not all([website_id, url]):
            return jsonify({'success': False, 'message': 'Website and URL are required'}), 400
        
        # Get website
        website = Website.query.filter_by(id=website_id, user_id=current_user.id).first()
        if not website:
            return jsonify({'success': False, 'message': 'Website not found'}), 404
        
        if not website.service_account_key:
            return jsonify({'success': False, 'message': 'Google Service Account key not configured for this website'}), 400
        
        # Submit to Google Indexing API
        success, result = GoogleIndexingAPI.submit_url(website.service_account_key, url, action)
        
        # Log the result
        log_entry = IndexingLog(
            website_id=website_id,
            url=url,
            action=action,
            status='success' if success else 'error',
            response_message=json.dumps(result) if success else str(result)
        )
        
        db.session.add(log_entry)
        db.session.commit()
        
        return jsonify({
            'success': success,
            'message': 'URL submitted successfully' if success else f'Submission failed: {result}',
            'result': result
        })
        
    except Exception as e:
        print(f"Error submitting indexing: {e}")
        return jsonify({'success': False, 'message': 'Submission failed'}), 500

@app.route('/api/update-service-account', methods=['POST'])
@login_required
def update_service_account():
    try:
        data = request.get_json()
        website_id = data.get('website_id')
        service_account_json = data.get('service_account_json')
        
        if not all([website_id, service_account_json]):
            return jsonify({'success': False, 'message': 'Website ID and Service Account JSON are required'}), 400
        
        # Validate JSON
        try:
            json.loads(service_account_json)
        except:
            return jsonify({'success': False, 'message': 'Invalid JSON format'}), 400
        
        # Get website
        website = Website.query.filter_by(id=website_id, user_id=current_user.id).first()
        if not website:
            return jsonify({'success': False, 'message': 'Website not found'}), 404
        
        # Update service account key
        website.service_account_key = service_account_json
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Service Account key updated successfully'})
        
    except Exception as e:
        print(f"Error updating service account: {e}")
        return jsonify({'success': False, 'message': 'Failed to update Service Account key'}), 500

@app.route('/api/fetch-post-content', methods=['POST'])
@login_required
def fetch_post_content():
    try:
        data = request.get_json()
        website_id = data.get('website_id')
        post_url = data.get('post_url')
        
        if not all([website_id, post_url]):
            return jsonify({'success': False, 'message': 'Website and URL are required'}), 400
        
        # Get website
        website = Website.query.filter_by(id=website_id, user_id=current_user.id).first()
        if not website:
            return jsonify({'success': False, 'message': 'Website not found'}), 404
        
        # Fetch post content
        post_data = WordPressAPI.get_post_by_url(website.website_url, website.wp_username, website.wp_api_key, post_url)
        
        if not post_data:
            return jsonify({'success': False, 'message': 'Post not found or unable to fetch'}), 404
        
        # Extract Yoast data
        yoast_data = WordPressAPI.get_yoast_data(post_data)
        
        return jsonify({
            'success': True,
            'post_data': {
                'id': post_data.get('id'),
                'title': post_data.get('title', {}).get('rendered', ''),
                'content': post_data.get('content', {}).get('rendered', ''),
                'excerpt': post_data.get('excerpt', {}).get('rendered', ''),
                'slug': post_data.get('slug', ''),
                'yoast': yoast_data
            }
        })
        
    except Exception as e:
        print(f"Error fetching post content: {e}")
        return jsonify({'success': False, 'message': 'Failed to fetch post content'}), 500

@app.route('/api/update-post-content', methods=['POST'])
@login_required
def update_post_content():
    try:
        data = request.get_json()
        website_id = data.get('website_id')
        post_id = data.get('post_id')
        updates = data.get('updates', {})
        
        if not all([website_id, post_id, updates]):
            return jsonify({'success': False, 'message': 'Website, post ID, and updates are required'}), 400
        
        # Get website
        website = Website.query.filter_by(id=website_id, user_id=current_user.id).first()
        if not website:
            return jsonify({'success': False, 'message': 'Website not found'}), 404
        
        # Update post
        success, result = WordPressAPI.update_post(website.website_url, website.wp_username, website.wp_api_key, post_id, updates)
        
        return jsonify({
            'success': success,
            'message': 'Post updated successfully' if success else f'Update failed: {result}',
            'result': result
        })
        
    except Exception as e:
        print(f"Error updating post content: {e}")
        return jsonify({'success': False, 'message': 'Failed to update post'}), 500

@app.route('/api/generate-bulk-csv', methods=['POST'])
@login_required
def generate_bulk_csv():
    try:
        data = request.get_json()
        website_id = data.get('website_id')
        urls = data.get('urls', [])
        
        if not all([website_id, urls]):
            return jsonify({'success': False, 'message': 'Website and URLs are required'}), 400
        
        # Get website
        website = Website.query.filter_by(id=website_id, user_id=current_user.id).first()
        if not website:
            return jsonify({'success': False, 'message': 'Website not found'}), 404
        
        # Generate CSV in memory
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['URL', 'ID', 'Title', 'Meta Description', 'Slug', 'Content'])
        
        # Process each URL
        for url in urls:
            if url.strip():
                post_data = WordPressAPI.get_post_by_url(website.website_url, website.wp_username, website.wp_api_key, url.strip())
                if post_data:
                    yoast_data = WordPressAPI.get_yoast_data(post_data)
                    writer.writerow([
                        url.strip(),
                        post_data.get('id', ''),
                        post_data.get('title', {}).get('rendered', ''),
                        yoast_data.get('description', ''),
                        post_data.get('slug', ''),
                        post_data.get('content', {}).get('rendered', '')[:500]  # Limit content length
                    ])
        
        # Create file response
        output.seek(0)
        file_data = io.BytesIO()
        file_data.write(output.getvalue().encode())
        file_data.seek(0)
        
        return send_file(
            file_data,
            mimetype='text/csv',
            as_attachment=True,
            download_name=f'bulk_edit_{website.website_name}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        )
        
    except Exception as e:
        print(f"Error generating CSV: {e}")
        return jsonify({'success': False, 'message': 'Failed to generate CSV'}), 500

@app.route('/api/websites')
@login_required
def get_websites():
    try:
        websites = Website.query.filter_by(user_id=current_user.id).all()
        websites_data = []
        for website in websites:
            websites_data.append({
                'id': website.id,
                'website_name': website.website_name,
                'website_url': website.website_url,
                'description': website.description,
                'created_at': website.created_at.strftime('%Y-%m-%d %H:%M'),
                'has_service_account': bool(website.service_account_key)
            })
        
        return jsonify({'success': True, 'websites': websites_data})
    except Exception as e:
        print(f"Error loading websites: {e}")
        return jsonify({'success': False, 'message': 'Failed to load websites'}), 500

@app.route('/api/completion-status')
@login_required
def completion_status():
    try:
        # Check various completion statuses
        has_websites = Website.query.filter_by(user_id=current_user.id).count() > 0
        has_api_config = Website.query.filter_by(user_id=current_user.id).filter(Website.service_account_key.isnot(None)).count() > 0
        has_indexing_activity = db.session.query(IndexingLog).join(Website).filter(Website.user_id == current_user.id).count() > 0
        has_edited_pages = True  # This could be tracked with actual page edits
        profile_updated = hasattr(current_user, 'profile_updated') and current_user.profile_updated
        
        return jsonify({
            'success': True,
            'has_websites': has_websites,
            'has_api_config': has_api_config,
            'has_indexing_activity': has_indexing_activity,
            'has_edited_pages': has_edited_pages,
            'profile_updated': profile_updated
        })
    except Exception as e:
        print(f"Error loading completion status: {e}")
        return jsonify({'success': False, 'message': 'Failed to load completion status'}), 500

@app.route('/api/update-profile', methods=['POST'])
@login_required
def update_profile():
    try:
        data = request.get_json()
        display_name = data.get('display_name', '').strip()
        email = data.get('email', '').strip().lower()
        current_password = data.get('current_password', '').strip()
        new_password = data.get('new_password', '').strip()
        
        if not display_name or not email:
            return jsonify({'success': False, 'message': 'Display name and email are required'}), 400
        
        # Check if new password is provided
        if new_password:
            if not current_password:
                return jsonify({'success': False, 'message': 'Current password is required to change password'}), 400
            
            if not current_user.check_password(current_password):
                return jsonify({'success': False, 'message': 'Current password is incorrect'}), 400
            
            if len(new_password) < 6:
                return jsonify({'success': False, 'message': 'New password must be at least 6 characters'}), 400
            
            current_user.set_password(new_password)
        
        # Check if email is already taken by another user
        if email != current_user.email:
            existing_user = User.query.filter_by(email=email).first()
            if existing_user and existing_user.id != current_user.id:
                return jsonify({'success': False, 'message': 'Email is already taken'}), 400
        
        # Check if username is already taken by another user
        if display_name != current_user.username:
            existing_user = User.query.filter_by(username=display_name).first()
            if existing_user and existing_user.id != current_user.id:
                return jsonify({'success': False, 'message': 'Username is already taken'}), 400
        
        # Update user data
        current_user.username = display_name
        current_user.email = email
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Profile updated successfully',
            'user': {
                'username': current_user.username,
                'email': current_user.email
            }
        })
        
    except Exception as e:
        print(f"Error updating profile: {e}")
        return jsonify({'success': False, 'message': 'Failed to update profile'}), 500

@app.route('/api/remove-website/<int:website_id>', methods=['DELETE'])
@login_required
def remove_website(website_id):
    try:
        website = Website.query.filter_by(id=website_id, user_id=current_user.id).first()
        if not website:
            return jsonify({'success': False, 'message': 'Website not found'}), 404
        
        # Delete associated indexing logs first (handled by cascade)
        db.session.delete(website)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Website removed successfully'})
        
    except Exception as e:
        print(f"Error removing website: {e}")
        return jsonify({'success': False, 'message': 'Failed to remove website'}), 500

@app.route('/api/dashboard-stats')
@login_required
def dashboard_stats():
    try:
        # Get recent indexing logs
        recent_logs = db.session.query(IndexingLog).join(Website).filter(
            Website.user_id == current_user.id
        ).order_by(IndexingLog.created_at.desc()).limit(10).all()
        
        # Format logs for response
        logs_data = []
        for log in recent_logs:
            logs_data.append({
                'url': log.url,
                'action': log.action,
                'status': log.status,
                'website_name': log.website.website_name,
                'created_at': log.created_at.strftime('%Y-%m-%d %H:%M')
            })
        
        return jsonify({
            'success': True,
            'recent_logs': logs_data
        })
        
    except Exception as e:
        print(f"Error loading dashboard stats: {e}")
        return jsonify({'success': False, 'message': 'Failed to load dashboard stats'}), 500

# Error handlers
@app.errorhandler(404)
def not_found(error):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Not found'}), 404
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Internal server error'}), 500
    return render_template('500.html'), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("Database tables created successfully!")
    
    print("=" * 60)
    print("🚀 WordPress API Manager - Starting Application")
    print("=" * 60)
    print("📍 Application URL: http://localhost:5000")
    print("📋 Features Available:")
    print("   • WordPress Website Management")
    print("   • Google Indexing API Integration")
    print("   • Single & Bulk Page Editing")
    print("   • Yoast SEO Integration")
    print("   • CSV Export/Import")
    print("=" * 60)
    print("✅ Server starting... Press CTRL+C to stop")
    print("=" * 60)
    
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)