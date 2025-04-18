# Используем официальный образ Python
FROM python:3.9-slim

# Устанавливаем метаданные
LABEL maintainer="K1PLinG Team"
LABEL version="2.0"
LABEL description="Silent Recon Tool for Bug Bounty"

# Устанавливаем зависимости
RUN apt-get update && apt-get install -y \
    nmap \
    curl \
    git \
    docker.io \
    golang-go \
    && rm -rf /var/lib/apt/lists/*

# Устанавливаем RustScan через Docker
RUN docker pull rustscan/rustscan:latest

# Устанавливаем dirsearch
RUN git clone https://github.com/maurosoria/dirsearch.git /opt/dirsearch \
    && cd /opt/dirsearch \
    && pip install -r requirements.txt

# Устанавливаем ffuf
RUN go install github.com/ffuf/ffuf@latest \
    && ln -s /go/bin/ffuf /usr/local/bin/ffuf

# Устанавливаем GoBuster
RUN go install github.com/OJ/gobuster/v3@latest \
    && ln -s /go/bin/gobuster /usr/local/bin/gobuster

# Создаем рабочую директорию
WORKDIR /app

# Копируем файлы
COPY requirements.txt .
COPY scripts/ /app/scripts/
COPY wordlists/ /app/wordlists/

# Устанавливаем Python зависимости
RUN pip install --no-cache-dir -r requirements.txt

# Делаем скрипт исполняемым
RUN chmod +x /app/scripts/silent_recon.py

# Создаем алиас для RustScan
RUN echo 'alias rustscan="docker run -it --rm --name rustscan rustscan/rustscan:latest"' >> /root/.bashrc

# Точка входа
ENTRYPOINT ["python", "/app/scripts/silent_recon.py"]