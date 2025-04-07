from app.db.session import engine
from app.models.secret import Secret, SecretLog
from app.db.base_class import Base

def init_db():
    Base.metadata.create_all(bind=engine)

if __name__ == "__main__":
    init_db()
    print("База данных инициализирована успешно!")
