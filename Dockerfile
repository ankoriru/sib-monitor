# Используем готовый образ от Microsoft со всеми зависимостями браузера
FROM mcr.microsoft.com/playwright/python:v1.42.0-jammy

WORKDIR /app

# Обновляем pip и копируем зависимости
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Устанавливаем только сам браузер Chromium
RUN playwright install chromium

# Копируем остальной код
COPY . .

# Запуск через uvicorn
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
