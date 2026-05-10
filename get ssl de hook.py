import subprocess
import re
import base64
import socket
import struct
import time
import os
import sys
TSHARK = r"C:\Program Files\Wireshark\tshark.exe"
PCAP = r"C:\Users\TAT\Desktop\login.pcap"
SERVER = "35.245.239.229"
PORT = 10836
DEVICE_ID = "79585394a068f10249efb6a5815e87b5e537fdf3"

seq = 0


def auto_capture():
    if os.path.exists(PCAP):
        os.remove(PCAP)

    print("[*] Đang khởi động capture...")
    proc = subprocess.Popen([
        TSHARK, "-i", "5",
        "-f", "host 35.245.239.229 and tcp port 10836",
        "-w", PCAP
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    time.sleep(2)  # Đợi tshark khởi động xong
    print("[!] Tshark sẵn sàng! Hãy BẬT GAME ngay!")

    for i in range(120):
        time.sleep(1)
        if os.path.exists(PCAP) and os.path.getsize(PCAP) > 1500:
            time.sleep(3)
            proc.terminate()
            print("[*] Bắt được login packet!")
            print("[!] Hãy TẮT GAME rồi nhấn Enter...")
            input()
            return True

    proc.terminate()
    print("[-] Timeout")
    return False

def extract_jwt_from_pcap():
    cmd = [TSHARK, "-r", PCAP, "-Y", "tcp.dstport == 10836 && tcp.len > 100",
           "-T", "fields", "-e", "tcp.payload"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    for line in result.stdout.strip().split('\n'):
        hex_data = line.replace(':', '')
        if len(hex_data) < 20:
            continue
        try:
            data = bytes.fromhex(hex_data)
            payload = bytearray(data[10:])
            payload[0] ^= (~1) & 0xFF
            raw = bytes(payload)
            idx = raw.find(b'eyJ')
            if idx >= 0:
                match = re.match(b'[A-Za-z0-9+/=_-]+', raw[idx:])
                if match:
                    jwt = match.group(0).decode('ascii')
                    jwt += "=" * (4 - len(jwt) % 4)
                    decoded = base64.b64decode(jwt).decode('utf-8', errors='ignore')
                    print(f"[JWT] {decoded[:80]}...")
                    return match.group(0).decode('ascii')
        except:
            pass
    return None


def write_thrift_compact_string(s):
    encoded = s.encode('utf-8')
    length = len(encoded)
    varint = bytearray()
    while length > 0x7F:
        varint.append((length & 0x7F) | 0x80)
        length >>= 7
    varint.append(length)
    return bytes(varint) + encoded


def build_login_thrift_compact(jwt_token):
    buf = bytearray()
    buf += bytes([0x18]) + write_thrift_compact_string(DEVICE_ID)
    buf += bytes([0x18]) + write_thrift_compact_string(jwt_token)
    buf += bytes([0x18]) + write_thrift_compact_string("windows")
    buf += b'\x00'
    return bytes(buf)


def build_empty_thrift():
    return b'\x00'


def encode_varint(n):
    buf = bytearray()
    while n > 0x7F:
        buf.append((n & 0x7F) | 0x80)
        n >>= 7
    buf.append(n)
    return bytes(buf)


def zigzag_encode(n):
    return (n << 1) ^ (n >> 63)


def zigzag_decode(n):
    return (n >> 1) ^ -(n & 1)


def build_bounty_reward_thrift(task_id):
    buf = bytearray()
    buf += bytes([0x16])
    buf += encode_varint(zigzag_encode(task_id))
    buf += b'\x00'
    return bytes(buf)


def build_guild_gift_thrift(tab):
    return bytes([0x12, 0x25, tab, 0x00])


def encode_packet(message_code, thrift_bytes):
    global seq
    seq = (seq + 1) & 0xFFFF
    data = bytearray(thrift_bytes)
    if len(data) > 0:
        data[0] ^= (~seq) & 0xFF
    header = struct.pack('>HHHI', 0x4000, seq, message_code, len(data))
    return header + bytes(data)


def recv_packet(sock):
    header = b""
    while len(header) < 10:
        chunk = sock.recv(10 - len(header))
        if not chunk:
            raise ConnectionError("Disconnected")
        header += chunk
    msg_code = struct.unpack('>H', header[4:6])[0]
    data_len = struct.unpack('>I', header[6:10])[0]
    data = b""
    while len(data) < data_len:
        chunk = sock.recv(data_len - len(data))
        if not chunk:
            raise ConnectionError("Disconnected")
        data += chunk
    return msg_code, data


def drain(sock, timeout=0.3, max_packets=200):
    sock.settimeout(timeout)
    for _ in range(max_packets):
        try:
            recv_packet(sock)
        except socket.timeout:
            break


def read_varint(data, pos):
    result = 0
    shift = 0
    while pos < len(data):
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            break
    return result, pos


def decode_bounty_info(data):
    task_ids = []
    i = 0
    vals = []

    while i < len(data) - 2:
        if data[i] == 0x15:
            i += 1
            val, i = read_varint(data, i)
            val = zigzag_decode(val)
            vals.append(val)
        else:
            i += 1

    for j in range(2, len(vals) - 1):
        v = vals[j]
        task_id = vals[j - 1]
        status = vals[j - 2]
        if 1700000000 < v < 1900000000 and task_id > 1000:
            print(f"  task_id={task_id} status={status}")
            if status == 11:
                task_ids.append(task_id)

    return task_ids


def do_bounty(sock):
    print("\n[=== BOUNTY ===]")
    sock.settimeout(5)
    sock.sendall(encode_packet(2991, build_empty_thrift()))
    print("[*] Sent CgGetBountyInfo")

    bounty_data = None
    for _ in range(200):
        try:
            msg_code, data = recv_packet(sock)
            if msg_code == 2992:
                bounty_data = data
                print("[+] Got BountyInfo!")
                break
        except socket.timeout:
            break

    if not bounty_data:
        print("[-] Không nhận được BountyInfo")
        return

    task_ids = decode_bounty_info(bounty_data)
    print(f"[*] Available: {task_ids}")

    if not task_ids:
        print("[!] Không có bounty available")
        return

    for tid in task_ids:
        print(f"[*] Claiming bounty {tid}...")
        sock.sendall(encode_packet(3000, build_bounty_reward_thrift(tid)))
        sock.settimeout(3)
        try:
            msg_code, data = recv_packet(sock)
            text = data.decode('utf-8', errors='ignore')
            print(f"  [REWARD] msgCode={msg_code} text={text[:60]}")
            if msg_code in [906, 2707]:
                print(f"  [+] CLAIM SUCCESS!")
        except socket.timeout:
            print("  [REWARD] timeout")


def do_guild_gift(sock):
    print("\n[=== GUILD GIFT ===]")

    # GetGuildGift
    sock.sendall(encode_packet(899, build_empty_thrift()))
    print("[*] Sent GetGuildGift")
    drain(sock, timeout=2)  # Tăng timeout lên 2s

    # Claim tab 1
    print("[*] Claiming tab 1...")
    sock.sendall(encode_packet(901, build_guild_gift_thrift(2)))
    sock.settimeout(5)  # Tăng timeout lên 5s
    try:
        msg_code, data = recv_packet(sock)
        text = data.decode('utf-8', errors='ignore')
        print(f"  [REWARD] msgCode={msg_code} text={text[:60]}")
        if msg_code in [902, 882]:
            print("  [+] Tab 1 SUCCESS!")
    except socket.timeout:
        print("  Tab 1 timeout")

    drain(sock, timeout=1)

    # Claim tab 2
    print("[*] Claiming tab 2...")
    sock.sendall(encode_packet(901, build_guild_gift_thrift(4)))
    sock.settimeout(5)
    try:
        msg_code, data = recv_packet(sock)
        text = data.decode('utf-8', errors='ignore')
        print(f"  [REWARD] msgCode={msg_code} text={text[:60]}")
        if msg_code in [902, 882]:
            print("  [+] Tab 2 SUCCESS!")
    except socket.timeout:
        print("  Tab 2 timeout")


def run_bot(jwt_token):
    global seq
    seq = 0
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((SERVER, PORT))
    print("[*] Connected!")

    # Login
    sock.sendall(encode_packet(1, build_login_thrift_compact(jwt_token)))
    print("[*] Sent CgLogIn")
    while True:
        try:
            msg_code, data = recv_packet(sock)
            print(f"  [RECV] msgCode={msg_code}")
            if msg_code == 2:
                print("[+] LOGIN SUCCESS!")
                break
        except socket.timeout:
            print("[-] Login timeout")
            sock.close()
            return

    # EnterGame
    sock.sendall(encode_packet(7, build_empty_thrift()))
    print("[*] Sent CgEnterGame")
    drain(sock, timeout=0.3)

    # Chạy các hoạt động
    do_bounty(sock)
    do_guild_gift(sock)

    sock.close()
    print("\n[*] Bot hoàn thành!")


if __name__ == "__main__":
    if not auto_capture():
        exit(1)

    jwt = extract_jwt_from_pcap()
    if not jwt:
        print("[-] Không tìm được JWT")
        exit(1)

    run_bot(jwt)