#!/usr/bin/env python3
"""
Notes CLI and Web Application
A command-line tool and web interface for managing notes with SQLite storage.
"""

import argparse
import sqlite3
import sys
import json
import base64
import hashlib
import os
import getpass
from datetime import datetime
from pathlib import Path
from typing import List, Tuple, Optional, Dict
from collections import defaultdict
from time import time
import re

# Encryption imports
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Web server imports
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_wtf.csrf import CSRFProtect
import os


def sanitize_input(input_str: str, max_length: int = 10000) -> str:
    """Sanitize user input to prevent various injection attacks."""
    if not input_str:
        return ""
    
    # Limit length to prevent DoS
    if len(input_str) > max_length:
        input_str = input_str[:max_length]
    
    # Strip whitespace
    input_str = input_str.strip()
    
    # Basic sanitization - remove null bytes and control characters
    input_str = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', input_str)
    
    return input_str


class NotesDatabase:
    """Handles all database operations for the notes application."""
    
    def __init__(self, db_path: str = None):
        if db_path is None:
            # Check for environment variable first
            db_path = os.environ.get('NOTES_DB_PATH')
            if db_path is None:
                # Get the directory where this script is located
                script_dir = os.path.dirname(os.path.abspath(__file__))
                db_path = os.path.join(script_dir, "notes.db")
        
        # Ensure the directory exists
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize the SQLite database and create the notes table if it doesn't exist."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,
                cmd TEXT NOT NULL,
                description TEXT,
                output TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create tags table for many-to-many relationship
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL
            )
        """)
        
        # Create note_tags junction table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS note_tags (
                note_id INTEGER,
                tag_id INTEGER,
                PRIMARY KEY (note_id, tag_id),
                FOREIGN KEY (note_id) REFERENCES notes (id) ON DELETE CASCADE,
                FOREIGN KEY (tag_id) REFERENCES tags (id) ON DELETE CASCADE
            )
        """)
        
        # Create attachments table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS attachments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                note_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                content_type TEXT,
                file_size INTEGER,
                file_data BLOB NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (note_id) REFERENCES notes (id) ON DELETE CASCADE
            )
        """)
        
        # Add new columns if they don't exist (for existing databases)
        try:
            cursor.execute("ALTER TABLE notes ADD COLUMN description TEXT")
        except sqlite3.OperationalError:
            pass  # Column already exists
        
        try:
            cursor.execute("ALTER TABLE notes ADD COLUMN output TEXT")
        except sqlite3.OperationalError:
            pass  # Column already exists
        
        try:
            cursor.execute("ALTER TABLE notes ADD COLUMN encrypted BOOLEAN DEFAULT 0")
        except sqlite3.OperationalError:
            pass  # Column already exists
        
        try:
            cursor.execute("ALTER TABLE notes ADD COLUMN salt TEXT")
        except sqlite3.OperationalError:
            pass  # Column already exists
        
        conn.commit()
        conn.close()
    
    def add_note(self, note_type: str, cmd: str, description: str = None, output: str = None, 
                encrypt_password: str = None, tags: List[str] = None) -> int:
        """Add a new note to the database, optionally encrypting only the cmd content."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        encrypted = False
        salt = None
        stored_cmd = cmd
        
        # Encrypt only the cmd content if password is provided
        if encrypt_password:
            stored_cmd, salt = self._encrypt_content(cmd, encrypt_password)
            encrypted = True
        
        cursor.execute(
            "INSERT INTO notes (type, cmd, description, output, encrypted, salt) VALUES (?, ?, ?, ?, ?, ?)",
            (note_type, stored_cmd, description, output, encrypted, salt)
        )
        
        note_id = cursor.lastrowid
        
        # Add tags if provided
        if tags:
            self._add_tags_to_note(cursor, note_id, tags)
        
        conn.commit()
        conn.close()
        
        return note_id
    
    def _add_tags_to_note(self, cursor, note_id: int, tags: List[str]):
        """Add tags to a note (internal method)."""
        for tag in tags:
            tag = tag.strip().lower()  # Normalize tag names
            if not tag:
                continue
                
            # Insert tag if it doesn't exist
            cursor.execute("INSERT OR IGNORE INTO tags (name) VALUES (?)", (tag,))
            
            # Get tag ID
            cursor.execute("SELECT id FROM tags WHERE name = ?", (tag,))
            tag_id = cursor.fetchone()[0]
            
            # Link note to tag
            cursor.execute("INSERT OR IGNORE INTO note_tags (note_id, tag_id) VALUES (?, ?)", 
                         (note_id, tag_id))
    
    def get_note_tags(self, note_id: int) -> List[str]:
        """Get all tags for a specific note."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT t.name 
            FROM tags t 
            JOIN note_tags nt ON t.id = nt.tag_id 
            WHERE nt.note_id = ?
            ORDER BY t.name
        """, (note_id,))
        
        tags = [row[0] for row in cursor.fetchall()]
        conn.close()
        return tags
    
    def get_tags_for_notes(self, note_ids: List[int]) -> Dict[int, List[str]]:
        """Get tags for multiple notes efficiently."""
        if not note_ids:
            return {}
        
        # Validate that all note_ids are integers
        if not all(isinstance(note_id, int) for note_id in note_ids):
            raise ValueError("All note_ids must be integers")
            
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create placeholders for the IN clause
        placeholders = ','.join(['?' for _ in note_ids])
        
        cursor.execute(f"""
            SELECT nt.note_id, t.name
            FROM note_tags nt
            JOIN tags t ON nt.tag_id = t.id
            WHERE nt.note_id IN ({placeholders})
            ORDER BY t.name
        """, note_ids)
        
        # Group tags by note_id
        tags_dict = {}
        for note_id, tag_name in cursor.fetchall():
            if note_id not in tags_dict:
                tags_dict[note_id] = []
            tags_dict[note_id].append(tag_name)
        
        conn.close()
        return tags_dict

    def get_all_tags(self) -> List[str]:
        """Get all tags in the database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT name FROM tags ORDER BY name")
        tags = [row[0] for row in cursor.fetchall()]
        conn.close()
        return tags
    
    def search_notes_by_tags(self, tags: List[str]) -> List[Tuple]:
        """Search notes by tags."""
        if not tags:
            return []
            
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create placeholders for the IN clause
        placeholders = ','.join(['?' for _ in tags])
        tags_lower = [tag.lower() for tag in tags]
        
        cursor.execute(f"""
            SELECT DISTINCT n.* 
            FROM notes n 
            JOIN note_tags nt ON n.id = nt.note_id 
            JOIN tags t ON nt.tag_id = t.id 
            WHERE t.name IN ({placeholders})
            ORDER BY n.created_at DESC
        """, tags_lower)
        
        notes = cursor.fetchall()
        conn.close()
        return notes
    
    def add_attachment(self, note_id: int, filename: str, content_type: str, file_data: bytes, password: str = None) -> int:
        """Add a file attachment to a note. If the note is encrypted, the file data will also be encrypted."""
        # Check if the note is encrypted
        note = self.get_note_by_id(note_id)
        if not note:
            raise ValueError(f"Note with ID {note_id} not found")
        
        note_id_db, note_type, cmd, description, output, created_at, encrypted, salt = note
        
        # If the note is encrypted, encrypt the file data
        actual_file_data = file_data
        if encrypted:
            if not password:
                raise ValueError("Password required to encrypt attachment for encrypted note")
            if not salt:
                raise ValueError("Encrypted note missing salt data")
            
            # Encrypt the file data using the note's salt
            actual_file_data = self._encrypt_file_data(file_data, password, salt)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        file_size = len(file_data)  # Store original file size
        
        cursor.execute("""
            INSERT INTO attachments (note_id, filename, content_type, file_size, file_data) 
            VALUES (?, ?, ?, ?, ?)
        """, (note_id, filename, content_type, file_size, actual_file_data))
        
        attachment_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return attachment_id
    
    def get_note_attachments(self, note_id: int) -> List[Tuple]:
        """Get all attachments for a note (without file data)."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, filename, content_type, file_size, created_at 
            FROM attachments 
            WHERE note_id = ? 
            ORDER BY created_at DESC
        """, (note_id,))
        
        attachments = cursor.fetchall()
        conn.close()
        return attachments
    
    def get_note_attachments_with_encryption_info(self, note_id: int) -> List[Tuple]:
        """Get all attachments for a note with encryption information (without file data)."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT a.id, a.filename, a.content_type, a.file_size, a.created_at, n.encrypted
            FROM attachments a
            JOIN notes n ON a.note_id = n.id
            WHERE a.note_id = ? 
            ORDER BY a.created_at DESC
        """, (note_id,))
        
        attachments = cursor.fetchall()
        conn.close()
        return attachments
    
    def get_attachment(self, attachment_id: int, password: str = None) -> Tuple:
        """Get a specific attachment with file data. If the note is encrypted, password is required."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT a.id, a.note_id, a.filename, a.content_type, a.file_size, a.file_data, a.created_at,
                   n.encrypted, n.salt
            FROM attachments a
            JOIN notes n ON a.note_id = n.id
            WHERE a.id = ?
        """, (attachment_id,))
        
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return None
        
        # Extract data
        att_id, note_id, filename, content_type, file_size, file_data, created_at, encrypted, salt = result
        
        # If the note is encrypted, decrypt the file data
        actual_file_data = file_data
        if encrypted:
            if not password:
                raise ValueError("Password required to decrypt attachment for encrypted note")
            if not salt:
                raise ValueError("Encrypted note missing salt data")
            
            # Decrypt the file data
            actual_file_data = self._decrypt_file_data(file_data, password, salt)
        
        return (att_id, note_id, filename, content_type, file_size, actual_file_data, created_at)
    
    def delete_attachment(self, attachment_id: int) -> bool:
        """Delete an attachment."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM attachments WHERE id = ?", (attachment_id,))
        success = cursor.rowcount > 0
        
        conn.commit()
        conn.close()
        return success
    
    def get_notes_by_type(self, note_type: str) -> List[Tuple]:
        """Retrieve all notes of a specific type (case-insensitive)."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT id, type, cmd, description, output, created_at, encrypted, salt FROM notes WHERE type = ? COLLATE NOCASE ORDER BY created_at DESC",
            (note_type,)
        )
        
        notes = cursor.fetchall()
        conn.close()
        
        return notes
    
    def get_notes_by_type_or_description(self, search_term: str) -> List[Tuple]:
        """Retrieve notes that match the search term in type or description (case-insensitive)."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Search in both type and description fields
        cursor.execute(
            "SELECT id, type, cmd, description, output, created_at, encrypted, salt FROM notes WHERE type LIKE ? COLLATE NOCASE OR description LIKE ? COLLATE NOCASE ORDER BY created_at DESC",
            (f"%{search_term}%", f"%{search_term}%")
        )
        
        notes = cursor.fetchall()
        conn.close()
        
        return notes
    
    def get_all_notes(self) -> List[Tuple]:
        """Retrieve all notes from the database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT id, type, cmd, description, output, created_at, encrypted, salt FROM notes ORDER BY created_at DESC"
        )
        
        notes = cursor.fetchall()
        conn.close()
        
        return notes
    
    def get_notes_grouped_by_type(self) -> dict:
        """Retrieve all notes grouped by type."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT type, id, cmd, description, output, created_at, encrypted, salt FROM notes ORDER BY type, created_at DESC"
        )
        
        notes = cursor.fetchall()
        conn.close()
        
        # Group notes by type
        grouped_notes = {}
        for note in notes:
            note_type = note[0]
            note_id = note[1]
            if note_type not in grouped_notes:
                grouped_notes[note_type] = []
            
            # Get tags for this note
            note_tags = self.get_note_tags(note_id)
            
            # Get attachments for this note with encryption info
            attachments = self.get_note_attachments_with_encryption_info(note_id)
            
            grouped_notes[note_type].append({
                'id': note_id,
                'cmd': note[2],
                'description': note[3],
                'output': note[4],
                'created_at': note[5],
                'encrypted': bool(note[6]),  # Convert to proper boolean
                'salt': note[7],
                'tags': note_tags,
                'attachments': attachments
            })
        
        return grouped_notes
    
    def get_decrypted_note_content(self, note_id: int, password: str) -> str:
        """Get the decrypted content of an encrypted note."""
        note = self.get_note_by_id(note_id)
        if not note:
            raise ValueError(f"Note with ID {note_id} not found")
        
        # Extract note fields (now includes encrypted and salt)
        note_id, note_type, cmd, description, output, created_at, encrypted, salt = note
        
        if not encrypted:
            return cmd  # Note is not encrypted, return as-is
        
        if not salt:
            raise ValueError("Encrypted note missing salt data")
        
        # Decrypt the content
        return self._decrypt_content(cmd, password, salt)
    
    def search_notes(self, query: str) -> List[Tuple]:
        """Search notes by type, command content, description, or tags (case-insensitive)."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Search in notes table and tags table
        cursor.execute("""
            SELECT DISTINCT n.id, n.type, n.cmd, n.description, n.output, n.created_at, n.encrypted, n.salt
            FROM notes n
            LEFT JOIN note_tags nt ON n.id = nt.note_id
            LEFT JOIN tags t ON nt.tag_id = t.id
            WHERE n.type LIKE ? COLLATE NOCASE 
               OR n.cmd LIKE ? COLLATE NOCASE 
               OR n.description LIKE ? COLLATE NOCASE
               OR t.name LIKE ? COLLATE NOCASE
            ORDER BY n.created_at DESC
        """, (f"%{query}%", f"%{query}%", f"%{query}%", f"%{query}%"))
        
        notes = cursor.fetchall()
        conn.close()
        
        return notes
    
    def get_all_types(self) -> List[str]:
        """Get all unique note types."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT DISTINCT type FROM notes ORDER BY type")
        types = [row[0] for row in cursor.fetchall()]
        
        conn.close()
        return types
    
    def delete_note(self, note_id: int) -> bool:
        """Delete a note by ID. Returns True if note was deleted, False if not found."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # First check if note exists
        cursor.execute("SELECT id FROM notes WHERE id = ?", (note_id,))
        if not cursor.fetchone():
            conn.close()
            return False
        
        # Delete the note
        cursor.execute("DELETE FROM notes WHERE id = ?", (note_id,))
        conn.commit()
        conn.close()
        
        return True
    
    def get_note_by_id(self, note_id: int) -> Optional[Tuple]:
        """Get a specific note by ID."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT id, type, cmd, description, output, created_at, encrypted, salt FROM notes WHERE id = ?",
            (note_id,)
        )
        
        note = cursor.fetchone()
        conn.close()
        
        return note
    
    def update_note(self, note_id: int, note_type: str, cmd: str, description: str = None, 
                   output: str = None, encrypt_password: str = None, current_password: str = None, 
                   keep_encrypted: bool = False, tags: List[str] = None) -> bool:
        """Update an existing note."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Get current note to check if it's encrypted
            current_note = self.get_note_by_id(note_id)
            if not current_note:
                return False
            
            is_currently_encrypted = bool(current_note[6])  # Convert to proper boolean
            current_salt = current_note[7]  # salt column
            
            # Handle encryption scenarios
            if encrypt_password:
                # User wants to encrypt the note with a new password
                if is_currently_encrypted and current_password:
                    # First verify the current password if note is encrypted
                    try:
                        current_decrypted = self.get_decrypted_note_content(note_id, current_password)
                        if current_decrypted is None:
                            return False
                    except:
                        return False
                
                # Encrypt with new password
                encrypted_cmd, salt = self._encrypt_content(cmd, encrypt_password)
                cursor.execute(
                    "UPDATE notes SET type = ?, cmd = ?, description = ?, output = ?, encrypted = ?, salt = ? WHERE id = ?",
                    (note_type, encrypted_cmd, description, output, True, salt, note_id)
                )
            elif keep_encrypted and is_currently_encrypted:
                # User wants to keep the note encrypted with the same password
                if current_password:
                    # First verify the current password
                    try:
                        current_decrypted = self.get_decrypted_note_content(note_id, current_password)
                        if current_decrypted is None:
                            return False
                    except:
                        return False
                    
                    # Re-encrypt with the same password but new content
                    encrypted_cmd, salt = self._encrypt_content(cmd, current_password)
                    cursor.execute(
                        "UPDATE notes SET type = ?, cmd = ?, description = ?, output = ?, encrypted = ?, salt = ? WHERE id = ?",
                        (note_type, encrypted_cmd, description, output, True, salt, note_id)
                    )
                else:
                    # No password provided but want to keep encrypted - only update non-content fields
                    cursor.execute(
                        "UPDATE notes SET type = ?, description = ?, output = ? WHERE id = ?",
                        (note_type, description, output, note_id)
                    )
            elif is_currently_encrypted and current_password and not keep_encrypted:
                # User wants to decrypt the note (remove encryption)
                # First verify the current password
                try:
                    current_decrypted = self.get_decrypted_note_content(note_id, current_password)
                    if current_decrypted is None:
                        return False
                except:
                    return False
                
                # Update with unencrypted content
                cursor.execute(
                    "UPDATE notes SET type = ?, cmd = ?, description = ?, output = ?, encrypted = ?, salt = ? WHERE id = ?",
                    (note_type, cmd, description, output, False, None, note_id)
                )
            elif is_currently_encrypted and not current_password:
                # Note is encrypted but no password provided - only update non-content fields
                cursor.execute(
                    "UPDATE notes SET type = ?, description = ?, output = ? WHERE id = ?",
                    (note_type, description, output, note_id)
                )
            else:
                # Note is not encrypted, just update normally
                cursor.execute(
                    "UPDATE notes SET type = ?, cmd = ?, description = ?, output = ?, encrypted = ?, salt = ? WHERE id = ?",
                    (note_type, cmd, description, output, False, None, note_id)
                )
            
            # Update tags if provided
            if tags is not None:
                # Remove existing tags for this note
                cursor.execute("DELETE FROM note_tags WHERE note_id = ?", (note_id,))
                # Add new tags
                if tags:
                    self._add_tags_to_note(cursor, note_id, tags)
            
            conn.commit()
            return True
            
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive a key from password and salt using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    def _encrypt_content(self, content: str, password: str) -> Tuple[str, str]:
        """Encrypt content with password. Returns (encrypted_content, salt_base64)."""
        # Generate a random salt
        salt = os.urandom(16)
        
        # Derive key from password and salt
        key = self._derive_key(password, salt)
        
        # Create Fernet instance and encrypt
        f = Fernet(key)
        encrypted_content = f.encrypt(content.encode())
        
        # Return base64 encoded encrypted content and salt
        return base64.b64encode(encrypted_content).decode(), base64.b64encode(salt).decode()
    
    def _decrypt_content(self, encrypted_content_b64: str, password: str, salt_b64: str) -> str:
        """Decrypt content with password and salt."""
        try:
            # Decode base64 encrypted content and salt
            encrypted_content = base64.b64decode(encrypted_content_b64.encode())
            salt = base64.b64decode(salt_b64.encode())
            
            # Derive key from password and salt
            key = self._derive_key(password, salt)
            
            # Create Fernet instance and decrypt
            f = Fernet(key)
            decrypted_content = f.decrypt(encrypted_content)
            
            return decrypted_content.decode()
        except Exception as e:
            raise ValueError(f"Failed to decrypt content. Wrong password or corrupted data: {e}")
    
    def _encrypt_file_data(self, file_data: bytes, password: str, salt_b64: str) -> bytes:
        """Encrypt file data using the same password and salt as the note."""
        try:
            # Decode salt from base64
            salt = base64.b64decode(salt_b64.encode())
            
            # Derive key from password and salt
            key = self._derive_key(password, salt)
            
            # Create Fernet instance and encrypt
            f = Fernet(key)
            encrypted_data = f.encrypt(file_data)
            
            return encrypted_data
        except Exception as e:
            raise ValueError(f"Failed to encrypt file data: {e}")
    
    def _decrypt_file_data(self, encrypted_file_data: bytes, password: str, salt_b64: str) -> bytes:
        """Decrypt file data using the same password and salt as the note."""
        try:
            # Decode salt from base64
            salt = base64.b64decode(salt_b64.encode())
            
            # Derive key from password and salt
            key = self._derive_key(password, salt)
            
            # Create Fernet instance and decrypt
            f = Fernet(key)
            decrypted_data = f.decrypt(encrypted_file_data)
            
            return decrypted_data
        except Exception as e:
            raise ValueError(f"Failed to decrypt file data. Wrong password or corrupted data: {e}")
    
    def is_note_encrypted(self, note_id: int) -> bool:
        """Check if a note is encrypted."""
        note = self.get_note_by_id(note_id)
        if not note:
            return False
        return bool(note[6])  # encrypted field is at index 6
    
    def get_note_encryption_info(self, note_id: int) -> Tuple[bool, str]:
        """Get note encryption status and salt. Returns (is_encrypted, salt_b64)."""
        note = self.get_note_by_id(note_id)
        if not note:
            return False, None
        return bool(note[6]), note[7]  # encrypted and salt fields
    

class NotesApp:
    """Main application class for the notes CLI and web interface."""
    
    def __init__(self):
        self.db = NotesDatabase()
    
    def add_note_cli(self, note_type: str, cmd: str, description: str = None, output: str = None, encrypt_password: str = None, json_output: bool = False, prompt_encrypt: bool = False):
        """Add a note via CLI."""
        try:
            # Handle password prompting for encryption
            if prompt_encrypt and not encrypt_password:
                response = input("Encrypt this note? (y/N): ").lower()
                if response in ['y', 'yes']:
                    encrypt_password = self._prompt_password("Enter encryption password: ", confirm=True)
                    if not encrypt_password:
                        if not json_output:
                            print("Note not added - password required for encryption.", file=sys.stderr)
                        return
            
            note_id = self.db.add_note(note_type, cmd, description, output, encrypt_password)
            
            if json_output:
                # Return JSON format
                result = {
                    "success": True,
                    "note": {
                        "id": note_id,
                        "type": note_type,
                        "command": "[ENCRYPTED]" if encrypt_password else cmd,
                        "description": description,
                        "output": output,
                        "encrypted": bool(encrypt_password),
                        "created_at": datetime.now().isoformat()
                    }
                }
                print(json.dumps(result, indent=2))
            else:
                # Return human-readable format
                print(f"Note added successfully with ID: {note_id}")
                print(f"Type: {note_type}")
                if encrypt_password:
                    print(f"Command: [ENCRYPTED]")
                    print(f"Encryption: Enabled")
                else:
                    print(f"Command: {cmd}")
                if description:
                    print(f"Description: {description}")
                if output:
                    print(f"Output: {output}")
        except Exception as e:
            if json_output:
                result = {
                    "success": False,
                    "error": str(e)
                }
                print(json.dumps(result, indent=2))
            else:
                print(f"Error adding note: {e}", file=sys.stderr)
            sys.exit(1)
    
    def get_notes_cli(self, note_type: str = None, search_term: str = None, show_description: bool = False, show_output: bool = False, only_commands: bool = False, decrypt_password: str = None, json_output: bool = False, note_id: int = None, tags: List[str] = None):
        """Get notes of a specific type via CLI, search across type/description, or all notes if no filters specified."""
        try:
            if note_id:
                # Specific note by ID
                note = self.db.get_note_by_id(note_id)
                if not note:
                    if json_output:
                        result = {"success": False, "error": f"Note with ID {note_id} not found"}
                        print(json.dumps(result, indent=2))
                    else:
                        print(f"Note with ID {note_id} not found", file=sys.stderr)
                    return
                notes = [note]
                filter_description = f"ID: {note_id}"
            elif tags:
                # Filter by tags
                notes = self.db.search_notes_by_tags(tags)
                tag_desc = ', '.join(tags)
                filter_description = f"tags: {tag_desc}"
                
                # If both tags and type are specified, filter the tag results by type
                if note_type:
                    notes = [note for note in notes if note[1].lower() == note_type.lower()]
                    filter_description = f"type: {note_type} and tags: {tag_desc}"
            elif search_term:
                # Search in both type and description
                notes = self.db.get_notes_by_type_or_description(search_term)
                filter_description = f"search term: '{search_term}'"
            elif note_type:
                notes = self.db.get_notes_by_type(note_type)
                filter_description = f"type: {note_type}"
            else:
                notes = self.db.get_all_notes()
                filter_description = "all notes"
            
            if not notes:
                if only_commands:
                    # In only-commands mode, just return silently (no output for no matches)
                    return
                elif json_output:
                    result = {
                        "success": True,
                        "notes": [],
                        "count": 0,
                        "filter": {"type": note_type, "search": search_term, "id": note_id},
                        "message": f"No notes found for {filter_description}"
                    }
                    print(json.dumps(result, indent=2))
                else:
                    print(f"No notes found for {filter_description}")
                return

            # Check for encrypted notes and prompt for password if needed
            encrypted_notes = [note for note in notes if note[6]]  # note[6] is encrypted column
            if encrypted_notes and not decrypt_password:
                specific_id_request = note_id is not None
                if self._should_prompt_for_password(len(encrypted_notes), specific_id_request):
                    decrypt_password = self._prompt_password("Enter decryption password: ")
                    if not decrypt_password:
                        if not json_output:
                            print("Skipping decryption - continuing with encrypted notes marked as [ENCRYPTED]")

            # Handle only-commands mode (simple output)
            if only_commands:
                for note in notes:
                    note_id, current_type, cmd, description, output, created_at, encrypted, salt = note
                    
                    # Handle encrypted content
                    if encrypted and decrypt_password:
                        try:
                            cmd = self.db._decrypt_content(cmd, decrypt_password, salt)
                        except Exception as e:
                            cmd = f"[DECRYPTION FAILED: {e}]"
                    elif encrypted:
                        cmd = "[ENCRYPTED - use --decrypt to view]"
                    
                    print(cmd)
                return
            
            if json_output:
                # Convert notes to JSON format
                notes_list = []
                for note in notes:
                    note_id, current_type, cmd, description, output, created_at, encrypted, salt = note
                    
                    # Handle encrypted content
                    display_cmd = cmd
                    if encrypted and decrypt_password:
                        try:
                            display_cmd = self.db._decrypt_content(cmd, decrypt_password, salt)
                        except Exception as e:
                            display_cmd = f"[DECRYPTION FAILED: {e}]"
                    elif encrypted:
                        display_cmd = "[ENCRYPTED]"
                    
                    note_dict = {
                        "id": note_id,
                        "type": current_type,
                        "command": display_cmd,
                        "encrypted": bool(encrypted),
                        "created_at": created_at
                    }
                    
                    # Include optional fields based on flags or if they have content
                    if show_description or description:
                        note_dict["description"] = description
                    if show_output or output:
                        note_dict["output"] = output
                    
                    notes_list.append(note_dict)
                
                result = {
                    "success": True,
                    "notes": notes_list,
                    "count": len(notes_list),
                    "filter": {
                        "type": note_type if note_type else None,
                        "search": search_term if search_term else None,
                        "show_description": show_description,
                        "show_output": show_output
                    }
                }
                print(json.dumps(result, indent=2))
            else:
                # Human-readable format
                if search_term:
                    print(f"Notes matching search term '{search_term}':")
                elif note_type:
                    print(f"Notes for type '{note_type}':")
                else:
                    print("All notes:")
                
                print("-" * 50)
                
                for note in notes:
                    note_id, current_type, cmd, description, output, created_at, encrypted, salt = note
                    
                    # Handle encrypted content
                    display_cmd = cmd
                    if encrypted and decrypt_password:
                        try:
                            display_cmd = self.db._decrypt_content(cmd, decrypt_password, salt)
                        except Exception as e:
                            display_cmd = f"[DECRYPTION FAILED: {e}]"
                    elif encrypted:
                        display_cmd = "[ENCRYPTED - use --decrypt to view]"
                    
                    print(f"ID: {note_id}")
                    print(f"Type: {current_type}")
                    print(f"Command: {display_cmd}")
                    if encrypted:
                        print(f"Encrypted: Yes")
                    if show_description and description:
                        print(f"Description: {description}")
                    if show_output and output:
                        print(f"Output: {output}")
                    print(f"Created: {created_at}")
                    print("-" * 30)
                
        except Exception as e:
            if json_output:
                result = {
                    "success": False,
                    "error": str(e)
                }
                print(json.dumps(result, indent=2))
            else:
                print(f"Error retrieving notes: {e}", file=sys.stderr)
            sys.exit(1)
    
    def delete_note_cli(self, note_id: int):
        """Delete a note via CLI."""
        try:
            # First, get the note details to show what will be deleted
            note = self.db.get_note_by_id(note_id)
            
            if not note:
                print(f"Note with ID {note_id} not found.")
                sys.exit(1)
            
            # Show note details
            note_id, note_type, cmd, description, output, created_at = note
            print(f"Found note to delete:")
            print(f"  ID: {note_id}")
            print(f"  Type: {note_type}")
            print(f"  Command: {cmd}")
            if description:
                print(f"  Description: {description}")
            print(f"  Created: {created_at}")
            print()
            
            # Ask for confirmation
            confirm = input("Are you sure you want to delete this note? (y/N): ").strip().lower()
            if confirm not in ['y', 'yes']:
                print("Deletion cancelled.")
                return
            
            # Delete the note
            if self.db.delete_note(note_id):
                print(f"Note with ID {note_id} has been deleted.")
            else:
                print(f"Failed to delete note with ID {note_id}.")
                sys.exit(1)
                
        except Exception as e:
            print(f"Error deleting note: {e}", file=sys.stderr)
            sys.exit(1)
    
    def update_note_cli(self, note_id: int, note_type: str = None, cmd: str = None, description: str = None, 
                       output: str = None, encrypt_password: str = None, current_password: str = None, 
                       decrypt: bool = False, json_output: bool = False):
        """Update a note via CLI."""
        try:
            # Get the current note
            current_note = self.db.get_note_by_id(note_id)
            if not current_note:
                if json_output:
                    result = {"success": False, "error": f"Note with ID {note_id} not found"}
                    print(json.dumps(result, indent=2))
                else:
                    print(f"Note with ID {note_id} not found", file=sys.stderr)
                return

            is_currently_encrypted = bool(current_note[6])
            
            # Prompt for current password if note is encrypted and we need to modify content
            if is_currently_encrypted and (cmd is not None or decrypt) and not current_password:
                current_password = self._prompt_password("Enter current decryption password: ")
                if not current_password:
                    if not json_output:
                        print("Current password required to modify encrypted note content.", file=sys.stderr)
                    return

            # Handle encryption logic
            keep_encrypted = not decrypt and (is_currently_encrypted or encrypt_password)
            
            # Use existing values if not provided
            final_type = note_type if note_type is not None else current_note[1]
            final_cmd = cmd if cmd is not None else (
                self.db.get_decrypted_note_content(note_id, current_password) 
                if is_currently_encrypted and current_password 
                else current_note[2]
            )
            final_description = description if description is not None else current_note[3]
            final_output = output if output is not None else current_note[4]

            success = self.db.update_note(
                note_id, final_type, final_cmd, final_description, final_output,
                encrypt_password, current_password, keep_encrypted
            )

            if success:
                if json_output:
                    result = {
                        "success": True,
                        "note": {
                            "id": note_id,
                            "type": final_type,
                            "encrypted": keep_encrypted,
                            "updated": True
                        }
                    }
                    print(json.dumps(result, indent=2))
                else:
                    print(f"Note {note_id} updated successfully!")
                    if keep_encrypted:
                        print("Note remains encrypted")
                    elif decrypt:
                        print("Note decrypted")
            else:
                if json_output:
                    result = {"success": False, "error": "Failed to update note"}
                    print(json.dumps(result, indent=2))
                else:
                    print("Failed to update note", file=sys.stderr)

        except Exception as e:
            if json_output:
                result = {"success": False, "error": str(e)}
                print(json.dumps(result, indent=2))
            else:
                print(f"Error updating note: {e}", file=sys.stderr)

    def _prompt_password(self, prompt: str, confirm: bool = False) -> str:
        """Prompt the user for a password, optionally confirming by re-typing."""
        import getpass
        
        if confirm:
            password = getpass.getpass(prompt + " (will be hidden): ")
            confirm_password = getpass.getpass("Confirm password: ")
            if password != confirm_password:
                print("Passwords do not match. Aborting.", file=sys.stderr)
                return None
            return password
        else:
            return getpass.getpass(prompt + " (will be hidden): ")

    def _should_prompt_for_password(self, num_encrypted_notes: int, specific_id_request: bool) -> bool:
        """Determine if we should prompt for password based on context."""
        if specific_id_request:
            # If user requested a specific note by ID, always prompt
            return True
        
        if num_encrypted_notes == 0:
            return False
        
        if num_encrypted_notes == 1:
            # For a single encrypted note, prompt without asking
            return True
        
        # For multiple encrypted notes, ask for permission first
        response = input(f"Found {num_encrypted_notes} encrypted notes. Prompt for password to decrypt them? (y/N): ").lower()
        return response in ['y', 'yes']

# Simple rate limiting storage
rate_limit_store = defaultdict(list)

def rate_limit_check(ip_address: str, max_requests: int = 100, window_minutes: int = 15) -> bool:
    """Simple rate limiting check. Returns True if request is allowed."""
    now = time()
    window_start = now - (window_minutes * 60)
    
    # Clean old requests
    rate_limit_store[ip_address] = [req_time for req_time in rate_limit_store[ip_address] if req_time > window_start]
    
    # Check if under limit
    if len(rate_limit_store[ip_address]) < max_requests:
        rate_limit_store[ip_address].append(now)
        return True
    
    return False

def create_web_app(notes_app: NotesApp) -> Flask:
    """Create and configure the Flask web application."""
    app = Flask(__name__)
    app.secret_key = os.urandom(24)
    
    # Enable CSRF protection
    csrf = CSRFProtect(app)
    
    # Configure CSRF to accept tokens from various sources
    app.config['WTF_CSRF_HEADERS'] = ['X-CSRFToken', 'X-CSRF-Token']
    
    # Security configurations
    app.config['WTF_CSRF_TIME_LIMIT'] = None  # Don't expire CSRF tokens
    
    # Security headers
    @app.after_request
    def add_security_headers(response):
        # Prevent XSS attacks
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        # Content Security Policy
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
            "font-src 'self' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
            "img-src 'self' data:; "
            "connect-src 'self';"
        )
        
        # Prevent MIME type sniffing
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        return response
    
    # Add custom template filters
    @app.template_filter('filesizeformat')
    def filesizeformat(num_bytes):
        """Format file size in human readable format."""
        if num_bytes is None:
            return "0 bytes"
        
        for unit in ['bytes', 'KB', 'MB', 'GB']:
            if num_bytes < 1024.0:
                if unit == 'bytes':
                    return f"{int(num_bytes)} {unit}"
                else:
                    return f"{num_bytes:.1f} {unit}"
            num_bytes /= 1024.0
        return f"{num_bytes:.1f} TB"
    
    # Add custom template filters
    @app.template_filter('filesizeformat')
    def filesizeformat(num_bytes):
        """Format file size in human readable format."""
        if num_bytes is None:
            return "0 bytes"
        
        for unit in ['bytes', 'KB', 'MB', 'GB']:
            if num_bytes < 1024.0:
                if unit == 'bytes':
                    return f"{int(num_bytes)} {unit}"
                else:
                    return f"{num_bytes:.1f} {unit}"
            num_bytes /= 1024.0
        return f"{num_bytes:.1f} TB"
    
    @app.route('/')
    def index():
        """Main page showing all notes grouped by type."""
        grouped_notes = notes_app.db.get_notes_grouped_by_type()
        types = notes_app.db.get_all_types()
        return render_template('index.html', grouped_notes=grouped_notes, types=types)
    
    @app.route('/add', methods=['GET', 'POST'])
    def add_note():
        """Add a new note via web form."""
        if request.method == 'POST':
            note_type = sanitize_input(request.form.get('type', ''), max_length=100)
            cmd = sanitize_input(request.form.get('cmd', ''), max_length=50000)
            description = sanitize_input(request.form.get('description', ''), max_length=1000) or None
            output = sanitize_input(request.form.get('output', ''), max_length=50000) or None
            encrypt_password = sanitize_input(request.form.get('encrypt_password', ''), max_length=200) or None
            tags_input = sanitize_input(request.form.get('tags', ''), max_length=1000)
            
            # Parse tags (comma-separated)
            tags = []
            if tags_input:
                tags = [sanitize_input(tag.strip(), max_length=50) for tag in tags_input.split(',') if tag.strip()]
            
            if not note_type or not cmd:
                flash('Both type and command are required!', 'error')
                return redirect(url_for('add_note'))
            
            try:
                note_id = notes_app.db.add_note(note_type, cmd, description, output, encrypt_password, tags)
                
                # Handle file uploads
                files = request.files.getlist('attachments')
                for file in files:
                    if file and file.filename:
                        file_data = file.read()
                        # Pass encryption password if the note is encrypted
                        notes_app.db.add_attachment(note_id, file.filename, file.content_type, file_data, encrypt_password)
                
                if encrypt_password:
                    flash(f'Encrypted note added successfully! (ID: {note_id})', 'success')
                else:
                    flash(f'Note added successfully! (ID: {note_id})', 'success')
                return redirect(url_for('index'))
            except Exception as e:
                flash(f'Error adding note: {e}', 'error')
        
        types = notes_app.db.get_all_types()
        all_tags = notes_app.db.get_all_tags()
        return render_template('add_note.html', types=types, all_tags=all_tags)
    
    @app.route('/edit/<int:note_id>', methods=['GET', 'POST'])
    def edit_note(note_id):
        """Edit an existing note via web form."""
        if request.method == 'POST':
            note_type = request.form.get('type', '').strip()
            cmd = request.form.get('cmd', '').strip()
            description = request.form.get('description', '').strip() or None
            output = request.form.get('output', '').strip() or None
            encrypt_password = request.form.get('encrypt_password', '').strip() or None
            current_password = request.form.get('current_password', '').strip() or None
            encrypt_note = request.form.get('encrypt_note') == 'on'
            tags_input = request.form.get('tags', '').strip()
            
            # Parse tags (comma-separated)
            tags = []
            if tags_input:
                tags = [tag.strip() for tag in tags_input.split(',') if tag.strip()]
            
            if not note_type or not cmd:
                flash('Both type and command are required!', 'error')
                return redirect(url_for('edit_note', note_id=note_id))
            
            # Get current note to check its encryption status
            current_note = notes_app.db.get_note_by_id(note_id)
            is_currently_encrypted = bool(current_note[6]) if current_note else False
            
            # Handle encryption logic
            final_encrypt_password = None
            if encrypt_note:
                # User wants to keep the note encrypted
                if encrypt_password:
                    # User provided a new password
                    final_encrypt_password = encrypt_password
                elif is_currently_encrypted:
                    # User wants to keep current encryption (no password change)
                    # We'll handle this by not providing encrypt_password but providing current_password
                    final_encrypt_password = None
                else:
                    # User wants to encrypt but didn't provide password for new encryption
                    flash('Password is required to encrypt the note!', 'error')
                    return redirect(url_for('edit_note', note_id=note_id))
            else:
                # User unchecked encrypt_note - wants to decrypt
                final_encrypt_password = None
            
            try:
                success = notes_app.db.update_note(
                    note_id, note_type, cmd, description, output, 
                    final_encrypt_password, current_password, encrypt_note, tags
                )
                
                # Handle file uploads for attachments
                files = request.files.getlist('attachments')
                for file in files:
                    if file and file.filename:
                        file_data = file.read()
                        # Determine which password to use for attachment encryption
                        attachment_password = None
                        if encrypt_note:  # User wants the note to be encrypted
                            if encrypt_password:
                                # New password provided
                                attachment_password = encrypt_password
                            elif is_currently_encrypted and current_password:
                                # Keep existing password (use current_password as it's the existing one)
                                attachment_password = current_password
                        # If encrypt_note is False, attachment_password stays None (unencrypted)
                        notes_app.db.add_attachment(note_id, file.filename, file.content_type, file_data, attachment_password)
                
                if success:
                    if encrypt_note and encrypt_password:
                        flash(f'Note updated and encrypted with new password successfully!', 'success')
                    elif encrypt_note and not encrypt_password and is_currently_encrypted:
                        flash(f'Note updated successfully! (encryption kept with existing password)', 'success')
                    elif encrypt_note and not encrypt_password and not is_currently_encrypted:
                        flash(f'Error: Password required to encrypt note!', 'error')
                        return redirect(url_for('edit_note', note_id=note_id))
                    elif not encrypt_note and is_currently_encrypted:
                        flash(f'Note updated and decrypted successfully!', 'success')
                    else:
                        flash(f'Note updated successfully!', 'success')
                    return redirect(url_for('index'))
                else:
                    flash('Failed to update note. Please check your current password if the note is encrypted.', 'error')
            except Exception as e:
                flash(f'Error updating note: {e}', 'error')
        
        # GET request - show edit form
        note = notes_app.db.get_note_by_id(note_id)
        if not note:
            flash('Note not found!', 'error')
            return redirect(url_for('index'))
        
        # Convert tuple to dict for easier template access
        note_dict = {
            'id': note[0],
            'type': note[1],
            'cmd': note[2],
            'description': note[3],
            'output': note[4],
            'created_at': note[5],
            'encrypted': bool(note[6]),  # Convert to proper boolean
            'salt': note[7]
        }
        
        # Get tags and attachments for this note
        note_tags = notes_app.db.get_note_tags(note_id)
        note_attachments = notes_app.db.get_note_attachments_with_encryption_info(note_id)
        
        # If note is encrypted, try to decrypt with password from query params (if provided)
        decrypted_cmd = None
        decrypt_password = request.args.get('password')
        if note_dict['encrypted'] and decrypt_password:
            try:
                decrypted_cmd = notes_app.db.get_decrypted_note_content(note_id, decrypt_password)
            except:
                pass  # Invalid password, will show encrypted placeholder
        
        types = notes_app.db.get_all_types()
        all_tags = notes_app.db.get_all_tags()
        return render_template('edit_note.html', note=note_dict, types=types, decrypted_cmd=decrypted_cmd, 
                             note_tags=note_tags, all_tags=all_tags, attachments=note_attachments)
    
    @app.route('/view/<int:note_id>')
    def view_note(note_id):
        """View a specific note by ID."""
        note = notes_app.db.get_note_by_id(note_id)
        if not note:
            flash('Note not found!', 'error')
            return redirect(url_for('index'))
        
        # Convert tuple to dict for easier template access
        note_dict = {
            'id': note[0],
            'type': note[1],
            'cmd': note[2],
            'description': note[3],
            'output': note[4],
            'created_at': note[5],
            'encrypted': bool(note[6]),
            'salt': note[7]
        }
        
        # Get tags and attachments for this note
        note_tags = notes_app.db.get_note_tags(note_id)
        note_attachments = notes_app.db.get_note_attachments_with_encryption_info(note_id)
        
        return render_template('view_note.html', note=note_dict, note_tags=note_tags, attachments=note_attachments)

    @app.route('/search')
    def search():
        """Search notes by type, command, description, or tags."""
        query = sanitize_input(request.args.get('q', ''), max_length=500)
        notes = []
        note_tags = {}
        
        if query:
            notes = notes_app.db.search_notes(query)
            # Get tags for all notes in search results
            if notes:
                note_ids = [note[0] for note in notes]
                note_tags = notes_app.db.get_tags_for_notes(note_ids)
        
        return render_template('search.html', notes=notes, query=query, note_tags=note_tags)
    
    @app.route('/export')
    def export_search_results():
        """Export search results as markdown."""
        query = request.args.get('q', '').strip()
        
        if not query:
            flash('No search query provided for export.', 'error')
            return redirect(url_for('search'))
        
        notes = notes_app.db.search_notes(query)
        
        if not notes:
            flash(f'No notes found for query "{query}" to export.', 'error')
            return redirect(url_for('search', q=query))
        
        # Generate markdown content
        markdown_content = generate_markdown_export(notes, query)
        
        # Create response with markdown file
        from flask import make_response
        response = make_response(markdown_content)
        response.headers['Content-Type'] = 'text/markdown; charset=utf-8'
        response.headers['Content-Disposition'] = f'attachment; filename="notes_search_{query.replace(" ", "_")}.md"'
        
        return response

    def generate_markdown_export(notes, query):
        """Generate markdown content from search results."""
        from datetime import datetime
        
        # Header
        markdown = f"# Notes Search Results\n\n"
        markdown += f"**Search Query:** `{query}`  \n"
        markdown += f"**Export Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  \n"
        markdown += f"**Total Results:** {len(notes)} note(s)\n\n"
        markdown += "---\n\n"
        
        # Notes
        for i, note in enumerate(notes, 1):
            note_id, note_type, cmd, description, output, created_at = note
            
            markdown += f"## {i}. {note_type}\n\n"
            
            if description:
                markdown += f"**Description:** {description}\n\n"
            
            markdown += f"**Command:**\n```bash\n{cmd}\n```\n\n"
            
            if output:
                markdown += f"**Example Output:**\n```\n{output}\n```\n\n"
            
            markdown += f"**Created:** {created_at}  \n"
            markdown += f"**ID:** {note_id}\n\n"
            markdown += "---\n\n"
        
        markdown += f"*Exported from Notes App on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n"
        
        return markdown
    
    @app.route('/delete/<int:note_id>', methods=['POST'])
    def delete_note(note_id):
        """Delete a note via web interface."""
        try:
            # Get note details for logging
            note = notes_app.db.get_note_by_id(note_id)
            if not note:
                flash(f'Note with ID {note_id} not found!', 'error')
                return redirect(url_for('index'))
            
            # Delete the note
            if notes_app.db.delete_note(note_id):
                flash(f'Note "{note[2][:50]}..." has been deleted successfully!', 'success')
            else:
                flash(f'Failed to delete note with ID {note_id}!', 'error')
                
        except Exception as e:
            flash(f'Error deleting note: {e}', 'error')
        
        return redirect(url_for('index'))
    
    @app.route('/decrypt/<int:note_id>', methods=['POST'])
    def decrypt_note(note_id):
        """Decrypt a note via web interface (AJAX endpoint)."""
        try:
            # Handle both JSON and form data requests
            if request.is_json:
                data = request.get_json()
                password = data.get('password', '').strip() if data else ''
            else:
                password = request.form.get('password', '').strip()
            
            if not password:
                return jsonify({'success': False, 'error': 'Password is required'})
            
            # Input validation and sanitization
            password = sanitize_input(password, max_length=1000)
            
            # Get and decrypt the note
            decrypted_content = notes_app.db.get_decrypted_note_content(note_id, password)
            if decrypted_content is None:
                return jsonify({'success': False, 'error': 'Note not found or failed to decrypt. Check your password.'})
            
            return jsonify({'success': True, 'decrypted_content': decrypted_content})
                
        except Exception as e:
            return jsonify({'success': False, 'error': f'Error decrypting note: {str(e)}'})

    @app.route('/attachment/<int:attachment_id>')
    def download_attachment(attachment_id):
        """Download a file attachment."""
        try:
            # First, get attachment info without decryption to check if encrypted
            conn = sqlite3.connect(notes_app.db.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT a.id, a.note_id, a.filename, a.content_type, a.file_size, a.file_data, a.created_at,
                       n.encrypted, n.salt
                FROM attachments a
                JOIN notes n ON a.note_id = n.id
                WHERE a.id = ?
            """, (attachment_id,))
            
            result = cursor.fetchone()
            conn.close()
            
            if not result:
                flash('Attachment not found!', 'error')
                return redirect(url_for('index'))
            
            att_id, note_id, filename, content_type, file_size, file_data, created_at, encrypted, salt = result
            
            # If not encrypted, serve directly
            if not encrypted:
                from flask import Response
                response = Response(
                    file_data,
                    mimetype=content_type or 'application/octet-stream',
                    headers={
                        'Content-Disposition': f'attachment; filename="{filename}"'
                    }
                )
                return response
            
            # If encrypted, check for password parameter
            password = request.args.get('password')
            if not password:
                # Redirect to a password prompt page
                flash('This attachment is encrypted. Password required for download.', 'warning')
                return redirect(url_for('attachment_password_prompt', attachment_id=attachment_id))
            
            # Try to decrypt with provided password
            try:
                decrypted_data = notes_app.db._decrypt_file_data(file_data, password, salt)
                from flask import Response
                response = Response(
                    decrypted_data,
                    mimetype=content_type or 'application/octet-stream',
                    headers={
                        'Content-Disposition': f'attachment; filename="{filename}"'
                    }
                )
                return response
            except ValueError as e:
                flash(f'Failed to decrypt attachment: Wrong password', 'error')
                return redirect(url_for('attachment_password_prompt', attachment_id=attachment_id))
            
        except Exception as e:
            flash(f'Error downloading attachment: {e}', 'error')
            return redirect(url_for('index'))

    @app.route('/attachment/<int:attachment_id>/delete', methods=['POST'])
    def delete_attachment(attachment_id):
        """Delete a file attachment."""
        try:
            # Get the attachment to find the note_id for redirect
            attachment = notes_app.db.get_attachment(attachment_id)
            note_id = attachment[1] if attachment else None
            
            success = notes_app.db.delete_attachment(attachment_id)
            if success:
                flash('Attachment deleted successfully!', 'success')
            else:
                flash('Failed to delete attachment!', 'error')
                
        except Exception as e:
            flash(f'Error deleting attachment: {e}', 'error')
        
        # Redirect back to the note edit page or index
        if note_id:
            return redirect(url_for('edit_note', note_id=note_id))
        else:
            return redirect(url_for('index'))
    
    @app.route('/attachment/<int:attachment_id>/password', methods=['GET', 'POST'])
    def attachment_password_prompt(attachment_id):
        """Prompt for password to download encrypted attachment."""
        # Get attachment info
        conn = sqlite3.connect(notes_app.db.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT a.filename, a.file_size, n.encrypted, n.type as note_type, n.description
            FROM attachments a
            JOIN notes n ON a.note_id = n.id
            WHERE a.id = ?
        """, (attachment_id,))
        
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            flash('Attachment not found!', 'error')
            return redirect(url_for('index'))
        
        filename, file_size, encrypted, note_type, note_description = result
        
        if not encrypted:
            # Not encrypted, redirect directly to download
            return redirect(url_for('download_attachment', attachment_id=attachment_id))
        
        if request.method == 'POST':
            password = sanitize_input(request.form.get('password', ''), max_length=500)
            if password:
                # Redirect to download with password parameter
                return redirect(url_for('download_attachment', attachment_id=attachment_id, password=password))
            else:
                flash('Password is required!', 'error')
        
        return render_template('attachment_password.html', 
                             attachment_id=attachment_id, 
                             filename=filename, 
                             file_size=file_size,
                             note_type=note_type,
                             note_description=note_description)
    
    @app.route('/get_csrf_token', methods=['GET'])
    def get_csrf_token():
        """Return a fresh CSRF token for AJAX requests."""
        from flask_wtf.csrf import generate_csrf
        try:
            return jsonify({'csrf_token': generate_csrf()})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    return app


def main():
    """Main entry point for the notes application."""
    parser = argparse.ArgumentParser(
        description="Notes CLI and Web Application - Secure password prompting prevents passwords from appearing in bash history",
        prog="notes",
        epilog="""
Examples:
  # Add encrypted note with prompted password (secure)
  notes add --type secret --body 'confidential data' --prompt-encrypt
  
  # Get specific encrypted note with prompted password
  notes get --id 5 --prompt-decrypt
  
  # Get all encrypted notes (will ask before prompting for password)
  notes get encrypted --prompt-decrypt
  
  # Update note and decrypt it
  notes update --id 3 --body 'new content' --decrypt
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Add command
    add_parser = subparsers.add_parser('add', help='Add a new note')
    add_parser.add_argument('--type', required=True, help='Type/category of the note')
    add_parser.add_argument('--body', required=True, help='Body content of the note (commands, text, or any content)')
    add_parser.add_argument('--description', help='Optional description of what the command does')
    add_parser.add_argument('--output', help='Optional example output of the command')
    add_parser.add_argument('--encrypt', help='Encrypt the command content with this password')
    add_parser.add_argument('--prompt-encrypt', action='store_true', help='Prompt for encryption password interactively')
    add_parser.add_argument('--json', action='store_true', help='Output result in JSON format')
    
    # Get command
    get_parser = subparsers.add_parser('get', help='Get notes by type, ID, or search term')
    get_parser.add_argument('type', nargs='?', help='Type/category of notes to retrieve (optional - shows all if not specified)')
    get_parser.add_argument('--type', dest='type_flag', help='Type/category of notes to retrieve (alternative to positional argument)')
    get_parser.add_argument('--id', type=int, help='Get a specific note by ID')
    get_parser.add_argument('--search', help='Search in both type and description fields (case-insensitive)')
    get_parser.add_argument('--tags', help='Filter by tags (comma-separated list, e.g., --tags web,security)')
    get_parser.add_argument('--show-description', action='store_true', help='Show descriptions in output')
    get_parser.add_argument('--show-output', action='store_true', help='Show example outputs in output')
    get_parser.add_argument('-c', '--only-commands', action='store_true', help='Output only the command/note bodies, one per line')
    get_parser.add_argument('--decrypt', help='Password to decrypt encrypted notes')
    get_parser.add_argument('--prompt-decrypt', action='store_true', help='Prompt for decryption password interactively')
    get_parser.add_argument('--json', action='store_true', help='Output result in JSON format')
    
    # Delete command
    delete_parser = subparsers.add_parser('delete', help='Delete a note by ID')
    delete_parser.add_argument('--id', type=int, required=True, help='ID of the note to delete')
    
    # Update command
    update_parser = subparsers.add_parser('update', help='Update an existing note')
    update_parser.add_argument('--id', type=int, required=True, help='ID of the note to update')
    update_parser.add_argument('--type', help='New type/category for the note')
    update_parser.add_argument('--body', help='New body content for the note')
    update_parser.add_argument('--description', help='New description for the note')
    update_parser.add_argument('--output', help='New example output for the note')
    update_parser.add_argument('--encrypt', help='Encrypt with new password')
    update_parser.add_argument('--decrypt', action='store_true', help='Decrypt the note (remove encryption)')
    update_parser.add_argument('--current-password', help='Current password for encrypted note')
    update_parser.add_argument('--json', action='store_true', help='Output result in JSON format')
    
    # Server command
    server_parser = subparsers.add_parser('server', help='Start the web server')
    server_parser.add_argument('--host', default='127.0.0.1', help='Host to bind the server to')
    server_parser.add_argument('--port', type=int, default=5000, help='Port to bind the server to')
    server_parser.add_argument('--debug', action='store_true', help='Run in debug mode')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Initialize the notes application
    notes_app = NotesApp()
    
    if args.command == 'add':
        # Handle password prompting for encryption
        encrypt_password = args.encrypt
        if args.prompt_encrypt and not encrypt_password:
            encrypt_password = notes_app._prompt_password("Enter encryption password: ", confirm=True)
        
        notes_app.add_note_cli(args.type, args.body, args.description, args.output, encrypt_password, args.json)
    
    elif args.command == 'get':
        # Handle both positional argument and --type flag (positional takes precedence)
        note_type = args.type or args.type_flag
        
        # Handle password prompting for decryption
        decrypt_password = args.decrypt
        if args.prompt_decrypt and not decrypt_password:
            decrypt_password = notes_app._prompt_password("Enter decryption password: ")
        
        # Parse tags if provided
        tags = None
        if args.tags:
            tags = [tag.strip() for tag in args.tags.split(',') if tag.strip()]
        
        notes_app.get_notes_cli(note_type, args.search, args.show_description, args.show_output, 
                               args.only_commands, decrypt_password, args.json, args.id, tags)
    
    elif args.command == 'server':
        print(f"Starting notes web server on {args.host}:{args.port}")
        app = create_web_app(notes_app)
        app.run(host=args.host, port=args.port, debug=args.debug)
    
    elif args.command == 'delete':
        notes_app.delete_note_cli(args.id)
    
    elif args.command == 'update':
        notes_app.update_note_cli(
            args.id, args.type, args.body, args.description, args.output,
            args.encrypt, args.current_password, args.decrypt, args.json
        )
    
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()


