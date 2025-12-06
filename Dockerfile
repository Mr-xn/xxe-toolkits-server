FROM python:3.11-slim

LABEL maintainer="Mr-xn"
LABEL description="Combined xxe-smb-server + fake-ftp-server for XXE exploitation"

# 默认环境变量（可在运行时覆盖）
ENV TZ=Asia/Shanghai \
    XXE_SMB_PUBLIC_IP=127.0.0.1 \
    XXE_SMB_WEB_PORT=8088 \
    XXE_SMB_SHARE_PATH=/tmp/share \
    XXE_FTP_PUBLIC_IP=127.0.0.1 \
    FAKE_FTP_PORT=2121 \
    FAKE_FTP_LOG_FILE="" \
    FAKE_FTP_HTTP_PORT=8087 \
    FAKE_FTP_FILE_PATH=/etc/passwd

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      tzdata \
      gcc \
      python3-dev \
      libffi-dev \
      libssl-dev \
      procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app

# 只安装 impacket（xxe-smb-server 的唯一第三方依赖）
RUN pip install --no-cache-dir impacket

RUN chmod +x /app/entrypoint.sh

# 暴露端口：
# - 8088/XXE_SMB_WEB_PORT: HTTP（DTD payload）for xxe-smb-server
# - 445: SMB（TCP，SimpleSMBServer）
# - 2121/FAKE_FTP_PORT: 假 FTP server
# - 8087/FAKE_FTP_HTTP_PORT: HTTP (DTD payload) for fake-ftp-server
EXPOSE 8088 445 2121 8087

ENTRYPOINT ["/app/entrypoint.sh"]
