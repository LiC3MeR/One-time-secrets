FROM python:3.9-slim

WORKDIR /app

# Установка зависимостей
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копирование проекта
COPY . .

# Кстановка пути до проекта
ENV PYTHONPATH=/app

# Запуск проекта
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
