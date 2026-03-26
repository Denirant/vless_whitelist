FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates git && \
    rm -rf /var/lib/apt/lists/*

# sing-box
RUN ARCH=$(dpkg --print-architecture) && \
    curl -fsSL "https://github.com/SagerNet/sing-box/releases/download/v1.11.4/sing-box-1.11.4-linux-${ARCH}.tar.gz" \
    | tar xz -C /tmp && \
    mv /tmp/sing-box-*/sing-box /usr/local/bin/sing-box && \
    chmod +x /usr/local/bin/sing-box && \
    rm -rf /tmp/sing-box-*

WORKDIR /app
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ .
RUN mkdir -p /app/data

ENV SING_BOX_PATH=/usr/local/bin/sing-box
EXPOSE 8080

CMD ["python3", "bot.py"]
