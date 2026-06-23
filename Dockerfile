FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN curl -L https://github.com/ethereum/solidity/releases/download/v0.8.20/solc-static-linux \
    -o /usr/local/bin/solc && chmod +x /usr/local/bin/solc

WORKDIR /scanner

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

EXPOSE 5001

CMD ["python", "app.py"]
