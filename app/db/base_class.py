from typing import Any
import uuid

from sqlalchemy.ext.declarative import as_declarative, declared_attr

@as_declarative()
class Base:
    id: Any
    __name__: str
    
    # Автоматически генерирует имя таблицы из имени класса
    @declared_attr
    def __tablename__(cls) -> str:
        return cls.__name__.lower()
