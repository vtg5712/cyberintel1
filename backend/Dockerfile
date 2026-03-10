FROM python:3.11-slim

WORKDIR /app

# System dependencies for Playwright, DNS tools, and ssdeep
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libfuzzy-dev \
    libssl-dev \
    dnsutils \
    whois \
    curl \
    wget \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright browsers
RUN playwright install --with-deps chromium

COPY . .

RUN mkdir -p /app/screenshots

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

**2. Jeśli nadal będą problemy z `ssdeep`, otwórz `backend/requirements.txt` i usuń tę linijkę:**
```
ssdeep==3.4
