import socket

def grab_banner(ip, port, timeout=2):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))

            try:
                banner = sock.recv(1024).decode(errors="ignore")
                return banner.strip()
            except:
                return ""
    except:
        return ""