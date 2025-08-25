#!/usr/bin/env python3
"""
Database Initialization Script for WordPress API Manager
"""

import os
from app import app, db

def init_database():
    """Initialize the database with all tables"""
    with app.app_context():
        # Remove existing database if it exists
        db_path = 'instance/wordpress_manager.db'
        if os.path.exists(db_path):
            print(f"Removing existing database: {db_path}")
            os.remove(db_path)
        
        # Ensure instance directory exists
        os.makedirs('instance', exist_ok=True)
        
        # Create all tables
        print("Creating database tables...")
        db.create_all()
        
        print("✅ Database initialized successfully!")
        print("📍 Database location: instance/wordpress_manager.db")
        print("🚀 You can now run the application with: python app.py")

if __name__ == '__main__':
    init_database()