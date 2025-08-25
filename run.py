#!/usr/bin/env python3
"""
WordPress API Manager - Main Application Entry Point
"""

import os
import sys
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db

def create_app():
    """Initialize the application"""
    with app.app_context():
        # Create database tables
        db.create_all()
        print("✅ Database initialized successfully!")
    
    return app

def main():
    """Main entry point"""
    print("=" * 60)
    print("🚀 WordPress API Manager - Starting Application")
    print("=" * 60)
    
    # Get configuration from environment or use defaults
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'
    
    print(f"📍 Server Configuration:")
    print(f"   • Host: {host}")
    print(f"   • Port: {port}")
    print(f"   • Debug: {debug}")
    print(f"   • Database: SQLite (wordpress_manager.db)")
    print("=" * 60)
    print("📋 Features Available:")
    print("   • WordPress Website Management")
    print("   • Google Indexing API Integration")
    print("   • Single & Bulk Page Editing")
    print("   • Yoast SEO Integration")
    print("   • CSV Export/Import")
    print("   • User Authentication & Profiles")
    print("=" * 60)
    print(f"🌐 Access the application at: http://localhost:{port}")
    print("=" * 60)
    print("✅ Server starting... Press CTRL+C to stop")
    print("=" * 60)
    
    # Create and run the application
    application = create_app()
    application.run(
        host=host,
        port=port,
        debug=debug,
        threaded=True
    )

if __name__ == '__main__':
    main()