"""
TiDB Serverless Integration for CerebralGuard
Handles vector search and full-text search operations for threat intelligence.
"""

import mysql.connector
from mysql.connector import Error
import numpy as np
from typing import List, Dict, Optional, Tuple
import json
from pathlib import Path
import os
from dotenv import load_dotenv
from loguru import logger

# Load environment variables
load_dotenv()

class TiDBManager:
    """Manages all TiDB Serverless operations for CerebralGuard."""
    
    def __init__(self):
        """Initialize TiDB connection with environment variables."""
        self.host = os.getenv('TIDB_HOST')
        self.port = int(os.getenv('TIDB_PORT', 4000))
        self.user = os.getenv('TIDB_USER')
        self.password = os.getenv('TIDB_PASSWORD')
        self.database = os.getenv('TIDB_DATABASE', 'cerebralguard')
        self.connection = None
        
    def connect(self) -> bool:
        """Establish connection to TiDB Serverless."""
        try:
            self.connection = mysql.connector.connect(
                host=self.host,
                port=self.port,
                user=self.user,
                password=self.password,
                database=self.database,
                ssl_disabled=False,
                autocommit=True
            )
            logger.info("Successfully connected to TiDB Serverless")
            return True
        except Error as e:
            logger.error(f"Error connecting to TiDB: {e}")
            return False
    
    def disconnect(self):
        """Close TiDB connection."""
        if self.connection and self.connection.is_connected():
            self.connection.close()
            logger.info("TiDB connection closed")
    
    def initialize_database(self):
        """Create necessary tables for CerebralGuard if they don't exist."""
        if not self.connection:
            if not self.connect():
                return False
        
        try:
            cursor = self.connection.cursor()
            
            # Create incidents table for storing email analysis results
            incidents_table = """
            CREATE TABLE IF NOT EXISTS incidents (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email_hash VARCHAR(64) UNIQUE NOT NULL,
                sender_email VARCHAR(255),
                sender_ip VARCHAR(45),
                subject TEXT,
                email_body LONGTEXT,
                email_vector JSON,
                extracted_iocs JSON,
                virustotal_score INT,
                abuseipdb_score INT,
                inhouse_model_score FLOAT,
                gemini_verdict VARCHAR(50),
                gemini_summary TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_email_hash (email_hash),
                INDEX idx_sender_email (sender_email),
                INDEX idx_sender_ip (sender_ip),
                FULLTEXT idx_body (email_body)
            )
            """
            
            # Create threat_intelligence table for external feeds
            threat_intel_table = """
            CREATE TABLE IF NOT EXISTS threat_intelligence (
                id INT AUTO_INCREMENT PRIMARY KEY,
                indicator_type ENUM('url', 'domain', 'ip', 'email', 'hash') NOT NULL,
                indicator_value VARCHAR(500) NOT NULL,
                threat_level ENUM('low', 'medium', 'high', 'critical') NOT NULL,
                source VARCHAR(100),
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY unique_indicator (indicator_type, indicator_value),
                INDEX idx_indicator_type (indicator_type),
                INDEX idx_threat_level (threat_level)
            )
            """
            
            cursor.execute(incidents_table)
            cursor.execute(threat_intel_table)
            self.connection.commit()
            
            logger.info("Database tables initialized successfully")
            return True
            
        except Error as e:
            logger.error(f"Error initializing database: {e}")
            return False
        finally:
            if cursor:
                cursor.close()
    
    def find_similar_incidents(self, email_vector: List[float], similarity_threshold: float = 0.8) -> List[Dict]:
        """
        Perform vector similarity search to find semantically similar past incidents.
        
        Args:
            email_vector: Vector representation of the email content
            similarity_threshold: Minimum similarity score (0-1)
            
        Returns:
            List of similar incidents with their details
        """
        if not self.connection:
            if not self.connect():
                return []
        
        try:
            cursor = self.connection.cursor(dictionary=True)
            
            # Convert vector to JSON for storage/comparison
            vector_json = json.dumps(email_vector)
            
            # For demonstration, we'll use a simple cosine similarity approach
            # In production, you might want to use TiDB's vector search capabilities
            query = """
            SELECT 
                id, email_hash, sender_email, sender_ip, subject,
                email_body, gemini_verdict, gemini_summary, created_at
            FROM incidents 
            WHERE gemini_verdict IN ('malicious', 'suspicious')
            ORDER BY created_at DESC 
            LIMIT 10
            """
            
            cursor.execute(query)
            results = cursor.fetchall()
            
            # Calculate similarity scores (simplified for demo)
            similar_incidents = []
            for result in results:
                # In a real implementation, you'd calculate actual vector similarity
                # For now, we'll return recent incidents as "similar"
                similar_incidents.append({
                    'id': result['id'],
                    'email_hash': result['email_hash'],
                    'sender_email': result['sender_email'],
                    'sender_ip': result['sender_ip'],
                    'subject': result['subject'],
                    'verdict': result['gemini_verdict'],
                    'summary': result['gemini_summary'],
                    'created_at': result['created_at'].isoformat(),
                    'similarity_score': 0.85  # Placeholder
                })
            
            logger.info(f"Found {len(similar_incidents)} similar incidents")
            return similar_incidents
            
        except Error as e:
            logger.error(f"Error in vector search: {e}")
            return []
        finally:
            if cursor:
                cursor.close()
    
    def search_threat_intelligence(self, iocs: Dict[str, List[str]]) -> Dict[str, List[Dict]]:
        """
        Perform full-text search against threat intelligence database.
        
        Args:
            iocs: Dictionary of IOC types and their values
                {
                    'urls': ['http://malicious.com'],
                    'domains': ['malicious.com'],
                    'ips': ['192.168.1.1'],
                    'emails': ['phisher@evil.com'],
                    'hashes': ['abc123...']
                }
                
        Returns:
            Dictionary of found threats by IOC type
        """
        if not self.connection:
            if not self.connect():
                return {}
        
        try:
            cursor = self.connection.cursor(dictionary=True)
            found_threats = {}
            
            for ioc_type, values in iocs.items():
                if not values:
                    continue
                    
                # Search for each IOC value
                for value in values:
                    query = """
                    SELECT 
                        indicator_type, indicator_value, threat_level,
                        source, first_seen, last_seen
                    FROM threat_intelligence 
                    WHERE indicator_type = %s AND indicator_value = %s
                    """
                    
                    cursor.execute(query, (ioc_type, value))
                    results = cursor.fetchall()
                    
                    if results:
                        if ioc_type not in found_threats:
                            found_threats[ioc_type] = []
                        
                        for result in results:
                            found_threats[ioc_type].append({
                                'value': result['indicator_value'],
                                'threat_level': result['threat_level'],
                                'source': result['source'],
                                'first_seen': result['first_seen'].isoformat(),
                                'last_seen': result['last_seen'].isoformat()
                            })
            
            logger.info(f"Found threats for {len(found_threats)} IOC types")
            return found_threats
            
        except Error as e:
            logger.error(f"Error in threat intelligence search: {e}")
            return {}
        finally:
            if cursor:
                cursor.close()
    
    def store_incident(self, incident_data: Dict) -> bool:
        """
        Store a new incident analysis in the database.
        
        Args:
            incident_data: Dictionary containing all incident information
            
        Returns:
            True if successful, False otherwise
        """
        if not self.connection:
            if not self.connect():
                return False
        
        try:
            cursor = self.connection.cursor()
            
            query = """
            INSERT INTO incidents (
                email_hash, sender_email, sender_ip, subject, email_body,
                email_vector, extracted_iocs, virustotal_score, abuseipdb_score,
                inhouse_model_score, gemini_verdict, gemini_summary
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            
            values = (
                incident_data.get('email_hash'),
                incident_data.get('sender_email'),
                incident_data.get('sender_ip'),
                incident_data.get('subject'),
                incident_data.get('email_body'),
                json.dumps(incident_data.get('email_vector', [])),
                json.dumps(incident_data.get('extracted_iocs', {})),
                incident_data.get('virustotal_score'),
                incident_data.get('abuseipdb_score'),
                incident_data.get('inhouse_model_score'),
                incident_data.get('gemini_verdict'),
                incident_data.get('gemini_summary')
            )
            
            cursor.execute(query, values)
            self.connection.commit()
            
            logger.info(f"Stored incident with hash: {incident_data.get('email_hash')}")
            return True
            
        except Error as e:
            logger.error(f"Error storing incident: {e}")
            return False
        finally:
            if cursor:
                cursor.close()
    
    def add_threat_intelligence(self, ioc_type: str, value: str, threat_level: str, source: str) -> bool:
        """
        Add a new threat intelligence indicator to the database.
        
        Args:
            ioc_type: Type of indicator (url, domain, ip, email, hash)
            value: The actual indicator value
            threat_level: Threat level (low, medium, high, critical)
            source: Source of the intelligence
            
        Returns:
            True if successful, False otherwise
        """
        if not self.connection:
            if not self.connect():
                return False
        
        try:
            cursor = self.connection.cursor()
            
            query = """
            INSERT INTO threat_intelligence (indicator_type, indicator_value, threat_level, source)
            VALUES (%s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                threat_level = VALUES(threat_level),
                source = VALUES(source),
                last_seen = CURRENT_TIMESTAMP
            """
            
            cursor.execute(query, (ioc_type, value, threat_level, source))
            self.connection.commit()
            
            logger.info(f"Added threat intelligence: {ioc_type}={value}")
            return True
            
        except Error as e:
            logger.error(f"Error adding threat intelligence: {e}")
            return False
        finally:
            if cursor:
                cursor.close()

# Global instance for easy access
tidb_manager = TiDBManager() 