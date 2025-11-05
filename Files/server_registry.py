import json
import os
from datetime import datetime, timezone
from typing import Dict, Set

REGISTRY_FILE = "server_registry.json"

class ServerRegistry:
    """Управление реестром серверов на испытательном сроке"""
    
    def __init__(self):
        self.registry: Dict[str, Dict] = {}
        self.load()
    
    def load(self):
        """Загрузить реестр из файла"""
        if os.path.exists(REGISTRY_FILE):
            try:
                with open(REGISTRY_FILE, 'r', encoding='utf-8') as f:
                    self.registry = json.load(f)
            except Exception as e:
                print(f"Warning: Failed to load registry: {e}")
                self.registry = {}
    
    def save(self):
        """Сохранить реестр в файл"""
        try:
            with open(REGISTRY_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.registry, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Warning: Failed to save registry: {e}")
    
    def add_to_probation(self, server_line: str):
        """Добавить сервер в реестр на испытательный срок"""
        self.registry[server_line] = {
            "status": "probation",
            "added_at": datetime.now(timezone.utc).isoformat()
        }
    
    def is_in_probation(self, server_line: str) -> bool:
        """Проверить, находится ли сервер в реестре"""
        return server_line in self.registry
    
    def remove_from_probation(self, server_line: str):
        """Удалить сервер из реестра"""
        if server_line in self.registry:
            del self.registry[server_line]
    
    def get_all_probation_servers(self) -> Set[str]:
        """Получить все серверы из реестра"""
        return set(self.registry.keys())
