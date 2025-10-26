import asyncpg
from datetime import datetime
import os
from dotenv import load_dotenv

load_dotenv()

class Database:
    def __init__(self):
        self.connection_pool = None
    
    async def connect(self):
        """Create database connection pool"""
        database_url = os.getenv('DATABASE_URL')
        if not database_url:
            raise ValueError("DATABASE_URL environment variable is required")
        
        self.connection_pool = await asyncpg.create_pool(database_url)
        await self.create_tables()
    
    async def create_tables(self):
        """Create necessary tables"""
        async with self.connection_pool.acquire() as conn:
            await conn.execute('''
                CREATE TABLE IF NOT EXISTS url_reports (
                    id SERIAL PRIMARY KEY,
                    url TEXT NOT NULL,
                    reporting_time TIMESTAMP NOT NULL,
                    reporter_name TEXT,
                    reporter_email TEXT,
                    image_data TEXT,
                    frequency INTEGER DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create index for better performance
            await conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_url_reports_url 
                ON url_reports(url)
            ''')
    
    async def insert_or_update_report(self, url: str, reporting_time: datetime, 
                                    reporter_name: str = None, reporter_email: str = None, 
                                    image_data: str = None):
        """Insert new report or update frequency if exists"""
        async with self.connection_pool.acquire() as conn:
            # Check if report exists for the same URL (regardless of time)
            existing = await conn.fetchrow(
                'SELECT id, frequency FROM url_reports WHERE url = $1',
                url
            )
            
            if existing:
                # Update frequency and timestamp
                await conn.execute(
                    'UPDATE url_reports SET frequency = $1, updated_at = $2 WHERE id = $3',
                    existing['frequency'] + 1, datetime.utcnow(), existing['id']
                )
                return existing['id'], existing['frequency'] + 1
            else:
                # Insert new report
                result = await conn.fetchrow(
                    '''INSERT INTO url_reports 
                    (url, reporting_time, reporter_name, reporter_email, image_data) 
                    VALUES ($1, $2, $3, $4, $5) 
                    RETURNING id, frequency''',
                    url, reporting_time, reporter_name, reporter_email, image_data
                )
                return result['id'], result['frequency']
    
    async def get_all_reports(self):
        """Retrieve all URL reports"""
        async with self.connection_pool.acquire() as conn:
            rows = await conn.fetch('''
                SELECT id, url, reporting_time, reporter_name, reporter_email, 
                       image_data, frequency, created_at, updated_at 
                FROM url_reports 
                ORDER BY created_at DESC
            ''')
            return rows

db = Database()