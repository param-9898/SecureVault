"""
File Manager for Encrypted Files
================================

Tracks encrypted files and their metadata.
"""

from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Final, List, Optional


@dataclass
class EncryptedFile:
    id: str
    user_id: str
    original_path: str
    encrypted_path: str
    file_size: int
    algorithm: str
    created_at: datetime
    
    @property
    def filename(self) -> str:
        return Path(self.original_path).name


class FileManager:
    """Manages tracking of encrypted files."""
    
    _SCHEMA: Final[str] = """
    CREATE TABLE IF NOT EXISTS encrypted_files (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        original_path TEXT NOT NULL,
        encrypted_path TEXT NOT NULL,
        file_size INTEGER NOT NULL,
        algorithm TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_files_user ON encrypted_files(user_id);
    """
    
    def __init__(self, db_path: Path | str) -> None:
        self._db_path = Path(db_path)
        self.initialize_db()
        
    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self._db_path,
            detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES
        )
        conn.row_factory = sqlite3.Row
        return conn

    def initialize_db(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._get_connection() as conn:
            conn.executescript(self._SCHEMA)
            conn.commit()
            
    def add_file(self, user_id: str, original_path: str, encrypted_path: str, 
                 size: int, algo: str = "Kyber+AES256-GCM") -> EncryptedFile:
        """Register a new encrypted file."""
        file_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO encrypted_files 
                (id, user_id, original_path, encrypted_path, file_size, algorithm, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (file_id, user_id, str(original_path), str(encrypted_path), 
                  size, algo, now.isoformat()))
            conn.commit()
            
        return EncryptedFile(
            id=file_id,
            user_id=user_id,
            original_path=str(original_path),
            encrypted_path=str(encrypted_path),
            file_size=size,
            algorithm=algo,
            created_at=now
        )
        
    def list_files(self, user_id: str) -> List[EncryptedFile]:
        """List all encrypted files for a user."""
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT * FROM encrypted_files 
                WHERE user_id = ? 
                ORDER BY created_at DESC
            """, (user_id,)).fetchall()
            
        return [self._row_to_file(row) for row in rows]
        
    def get_file(self, file_id: str) -> Optional[EncryptedFile]:
        """Get file by ID."""
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM encrypted_files WHERE id = ?", (file_id,)).fetchone()
            if not row:
                return None
            return self._row_to_file(row)
            
    def delete_file_record(self, file_id: str) -> None:
        """Remove file record (does not delete actual file)."""
        with self._get_connection() as conn:
            conn.execute("DELETE FROM encrypted_files WHERE id = ?", (file_id,))
            conn.commit()

    def _row_to_file(self, row: sqlite3.Row) -> EncryptedFile:
        return EncryptedFile(
            id=row["id"],
            user_id=row["user_id"],
            original_path=row["original_path"],
            encrypted_path=row["encrypted_path"],
            file_size=row["file_size"],
            algorithm=row["algorithm"],
            created_at=datetime.fromisoformat(row["created_at"])
        )
