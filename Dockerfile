# Используем стабильный образ от Microsoft с готовым окружением для браузеров
FROM mcr.microsoft.com/playwright/python:v1.42.0-jammy

WORKDIR /app

# Устанавливаем системную библиотеку для работы с PostgreSQL
RUN apt-get update && apt-get install -y libpq-dev && rm -rf /var/lib/apt/lists/*

# Обновляем pip и устанавливаем зависимости Python
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Устанавливаем бинарный файл браузера Chromium
RUN playwright install chromium

# Копируем весь код проекта
COPY . .

# Открываем порт для FastAPI
EXPOSE 8000

# Запуск приложения
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
