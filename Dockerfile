FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-17-jdk-headless \
    wget \
    unzip \
    apksigner \
    zipalign \
    && rm -rf /var/lib/apt/lists/*


RUN wget -q https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool -O /usr/local/bin/apktool && \
    wget -q https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.8.1.jar -O /usr/local/bin/apktool.jar && \
    chmod +x /usr/local/bin/apktool

RUN echo '#!/bin/sh\njava -jar /usr/local/bin/apktool.jar "$@"' > /usr/local/bin/apktool && \
    chmod +x /usr/local/bin/apktool

COPY patch_apk.py .
COPY requirements.txt .
RUN pip install -r requirements.txt

ENTRYPOINT ["python3", "patch_apk.py"]
