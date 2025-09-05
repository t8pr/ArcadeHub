import json
import os
import uuid
from datetime import datetime
from typing import List, Dict, Any

class GamesDB:
    def __init__(self, db_file='games_database.json'):
        self.db_file = db_file
        self._ensure_db_file()
    
    def _ensure_db_file(self):
        """Create the database file if it doesn't exist"""
        if not os.path.exists(self.db_file):
            with open(self.db_file, 'w', encoding='utf-8') as f:
                json.dump({"games": [], "last_updated": str(datetime.now())}, f, ensure_ascii=False, indent=2)
    
    def _read_db(self):
        """Read the database file"""
        try:
            with open(self.db_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return {"games": [], "last_updated": str(datetime.now())}
    
    def _write_db(self, data):
        """Write to the database file"""
        data['last_updated'] = str(datetime.now())
        with open(self.db_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2, default=str)
    
    def add_game(self, game_data: Dict[str, Any]) -> str:
        """Add a new game to the database"""
        db = self._read_db()
        
        # Generate unique ID and slug
        game_id = str(uuid.uuid4())
        game_data['id'] = game_id
        game_data['slug'] = self._generate_slug(game_data['title'])
        game_data['created_at'] = str(datetime.now())
        game_data['updated_at'] = str(datetime.now())
        game_data['developer_id'] = game_data.get('developer_id')
        
        # Set default values
        game_data.setdefault('rating', 0.0)
        game_data.setdefault('downloads', 0)
        game_data.setdefault('status', 'published')
        game_data.setdefault('price', 0.0)
        
        db['games'].append(game_data)
        self._write_db(db)
        
        return game_id
    
    def delete_game(self, game_id: str) -> bool:
        """Delete a game"""
        db = self._read_db()
        for i, game in enumerate(db['games']):
            if game['id'] == game_id:
                del db['games'][i]
                self._write_db(db)
                return True
        return False
    
    def _generate_slug(self, title: str) -> str:
        """Generate a URL-friendly slug from the title"""
        import re
        from arabic_reshaper import reshape
        from bidi.algorithm import get_display
        
        # Basic slug generation (you might want to improve this)
        slug = re.sub(r'[^\w\s-]', '', title.lower())
        slug = re.sub(r'[-\s]+', '-', slug).strip('-')
        return slug
    
    def get_game_by_id(self, game_id: str) -> Dict[str, Any]:
        """Get a game by its ID"""
        db = self._read_db()
        for game in db['games']:
            if game['id'] == game_id:
                return game
        return None
    
    def get_game_by_slug(self, slug: str) -> Dict[str, Any]:
        """Get a game by its slug"""
        db = self._read_db()
        for game in db['games']:
            if game['slug'] == slug:
                return game
        return None
    
    def get_developer_games(self, developer_id: str) -> List[Dict[str, Any]]:
        """Get all games by a specific developer"""
        db = self._read_db()
        return [game for game in db['games'] if game['developer_id'] == developer_id]
    
    def get_all_games(self) -> List[Dict[str, Any]]:
        """Get all published games"""
        db = self._read_db()
        return [game for game in db['games'] if game['status'] == 'published']
    
    def update_game(self, game_id: str, updates: Dict[str, Any]) -> bool:
        """Update a game"""
        db = self._read_db()
        for i, game in enumerate(db['games']):
            if game['id'] == game_id:
                updates['updated_at'] = str(datetime.now())
                db['games'][i].update(updates)
                self._write_db(db)
                return True
        return False
    
    def delete_game(self, game_id: str) -> bool:
        """Delete a game"""
        db = self._read_db()
        for i, game in enumerate(db['games']):
            if game['id'] == game_id:
                del db['games'][i]
                self._write_db(db)
                return True
        return False

# Initialize games database
games_db = GamesDB()