# Używamy oficjalnego obrazu Pythona (np. Python 3.9-slim)
FROM python:3.9-slim

# Ustawiamy katalog roboczy w kontenerze
WORKDIR /app

# Kopiujemy plik z zależnościami i instalujemy je
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Kopiujemy cały kod aplikacji do katalogu roboczego
COPY . .

# Ustawiamy zmienne środowiskowe, jeśli są potrzebne (opcjonalnie)
ENV FLASK_APP=app.py
ENV FLASK_ENV=production

# Expose port, na którym aplikacja będzie działać
EXPOSE 8080

# Uruchamiamy aplikację (przykładowo przy użyciu Gunicorna)
CMD ["gunicorn", "-b", "0.0.0.0:8080", "app:app"]
