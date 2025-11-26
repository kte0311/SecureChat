import tkinter as tk
from tkinter import filedialog, messagebox
import threading, socket, os
from key_utils import load_public_key, load_private_key
from crypto_utils import generate_aes_key, rsa_encrypt, encrypt_message_aes, decrypt_message_aes, encrypt_file_aes

# 파일 관련 기본 경로 설정
BASE_DIR = "files"
FILES_DIR = os.path.join(BASE_DIR, "test_files")
os.makedirs(FILES_DIR, exist_ok=True)


# 말풍선 클래스
class ChatBubble(tk.Frame):
    def __init__(self, master, text, side="left", color="#F1F0F0", text_color="#000"):
        super().__init__(master, bg=master["bg"])
        label = tk.Label(
            self, text=text, bg=color, fg=text_color, wraplength=320,
            justify="left" if side == "left" else "right",
            font=("Arial", 11), padx=10, pady=6, bd=0, relief="solid",
        )
        label.pack(anchor="w" if side == "left" else "e")


# 채팅 영역 클래스
class ChatArea(tk.Frame):
    def __init__(self, master, bg):
        super().__init__(master, bg=bg)

        # Canvas + Scrollbar 구조, 스크롤 가능 
        self.canvas = tk.Canvas(self, bg=bg, highlightthickness=0)
        self.scrollbar = tk.Scrollbar(self, command=self.canvas.yview)
        self.scrollable_frame = tk.Frame(self.canvas, bg=bg)
        self.window_id = self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        
        # 프레임 크기 변경 시 자동 스크롤 영역 업데이트
        self.scrollable_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfig(self.window_id, width=e.width))
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    # 일반 채팅 메시지 추가 (좌/우측 정렬)
    def add_bubble(self, text, side="left"):
        color = "#CBE7FF" if side == "right" else "#F1F0F0"   # 클라이언트는 파랑 계열
        text_color = "#003366" if side == "right" else "#000"
        line = tk.Frame(self.scrollable_frame, bg=self.scrollable_frame["bg"])
        line.pack(fill="x", pady=3)
        bubble = ChatBubble(line, text, side, color, text_color)
        bubble.pack(side="right" if side == "right" else "left",
                    padx=(50, 10) if side == "right" else (10, 50))
        self.canvas.update_idletasks()
        self.canvas.yview_moveto(1)

    # 시스템 메시지 (상태 안내)
    def add_system_message(self, text):
        lbl = tk.Label(self.scrollable_frame, text=text, bg=self.scrollable_frame["bg"],
                       fg="#777", font=("Arial", 10, "italic"))
        lbl.pack(anchor="center", pady=3)
        self.canvas.update_idletasks()
        self.canvas.yview_moveto(1)


# 클라이언트 UI 메인 클래스
class ClientUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("💙 Client - Secure Chat")
        self.geometry("520x640")
        self.configure(bg="#EAF2FB")

        # 클라이언트 소켓 및 AES 키 저장 변수
        self.client_socket = None
        self.aes_key = None

        # 상단 헤더 UI 
        header = tk.Frame(self, bg="#1E90FF", height=50)
        header.pack(fill=tk.X)
        tk.Label(header, text="CLIENT", bg="#1E90FF", fg="white", font=("Arial", 15, "bold")).pack(side=tk.LEFT, padx=15)
        self.status_label = tk.Label(header, text="Disconnected", bg="#1E90FF", fg="white", font=("Arial", 11))
        self.status_label.pack(side=tk.RIGHT, padx=15)
    
        # 중앙 채팅 영역
        self.chat_area = ChatArea(self, "#F8FBFF")
        self.chat_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # 하단 메시지 입력창 + 버튼
        bottom = tk.Frame(self, bg="#EAF2FB")
        bottom.pack(fill=tk.X, pady=10)
        self.msg_entry = tk.Entry(bottom, font=("Arial", 12))
        self.msg_entry.pack(side=tk.LEFT, padx=10, pady=5, ipady=4, expand=True, fill=tk.X)
        tk.Button(bottom, text="📎", bg="#87CEFA", fg="white", width=3, command=self.send_file).pack(side=tk.LEFT, padx=3)
        tk.Button(bottom, text="Send", bg="#1E90FF", fg="white", width=6, command=self.send_message).pack(side=tk.RIGHT, padx=10)

        self.connect_window()


    # 서버 연결 창 (IP/Port 입력용 팝업)
    def connect_window(self):
        win = tk.Toplevel(self)
        win.title("Connect to Server")
        win.geometry("300x160")
        win.configure(bg="#EAF2FB")
        win.grab_set()   # 다른 창 조작 방지

        # IP / Port 입력 UI
        tk.Label(win, text="Server IP:", bg="#EAF2FB").pack(pady=5)
        ip_entry = tk.Entry(win)
        ip_entry.insert(0, "127.0.0.1")
        ip_entry.pack()
        tk.Label(win, text="Port:", bg="#EAF2FB").pack(pady=5)
        port_entry = tk.Entry(win)
        port_entry.insert(0, "5000")
        port_entry.pack()

        # 연결 버튼 클릭 시 connect_server() 호출
        def connect():
            ip = ip_entry.get()
            port = int(port_entry.get())
            win.destroy()
            self.connect_server(ip, port)

        tk.Button(win, text="Connect", bg="#1E90FF", fg="white", command=connect).pack(pady=10)


    # 서버 연결 및 키 교환 (RSA + AES 세션키)
    def connect_server(self, host, port):
        try:
            # 1. 서버 소켓 연결
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((host, port))
            self.status_label.config(text=f"Connected: {host}:{port}")

            # 2. 공개키 교환 (RSA)
            client_pub = load_public_key("keys/client_public.pem")
            server_pub = self.client_socket.recv(4096)
            self.client_socket.send(client_pub)

            # 3. AES 세션키 생성 후 서버 공개키로 암호화하여 전송
            self.aes_key = generate_aes_key()
            self.client_socket.send(rsa_encrypt(server_pub, self.aes_key))

            # 4. 키 정보 표시
            self.chat_area.add_system_message(f" RSA 공개키 길이: {len(server_pub)} bytes")
            self.chat_area.add_system_message(f" AES 세션키 길이: {len(self.aes_key)} bytes")
            self.chat_area.add_system_message(f" AES 세션키 (HEX): {self.aes_key.hex().upper()}")
            self.chat_area.add_system_message("✅ AES 세션키 교환 완료")

            # 5. 별도 스레드로 메시지 수신 루프 실행
            threading.Thread(target=self.receive_loop, daemon=True).start()

        except Exception as e:
            messagebox.showerror("Connection Error", str(e))


    # 서버로부터 AES 암호문 수신 및 복호화 루프
    def receive_loop(self):
        while True:
            try:
                enc_data = self.client_socket.recv(4096)
                if not enc_data:
                    break
                # 수신 암호문 복호화 (AES)
                msg = decrypt_message_aes(self.aes_key, enc_data)

                # 암호문과 복호문 모두 출력
                cipher_hex = enc_data.hex().upper()
                self.chat_area.add_system_message(f"[수신 암호문] {cipher_hex[:80]}...")
                self.chat_area.add_bubble(f"[서버 복호화 결과] {msg}", "left")
            except Exception:
                break


    # 메시지 송신 (AES 암호화 적용)
    def send_message(self):
        msg = self.msg_entry.get().strip()
        if not msg or not self.client_socket:
            return
        
        # AES 암호화 후 서버로 전송
        enc_msg = encrypt_message_aes(self.aes_key, msg)
        self.client_socket.send(enc_msg)

        # 송신 암호문과 평문 표시
        self.chat_area.add_system_message(f"[송신 암호문] {enc_msg.hex().upper()[:80]}...")
        self.chat_area.add_bubble(msg, "right")
        self.msg_entry.delete(0, tk.END)


    # 파일 전송 (AES 파일 암호화 적용)
    def send_file(self):
        if not self.client_socket:
            messagebox.showwarning("경고", "서버에 먼저 연결하세요.")
            return
        path = filedialog.askopenfilename(initialdir=FILES_DIR)
        if not path:
            return

        filename = os.path.basename(path)

        # 1. 서버에 파일 전송 시작 알림
        self.client_socket.send(encrypt_message_aes(self.aes_key, "__FILE_START__"))
        self.client_socket.send(encrypt_message_aes(self.aes_key, filename))

        # 2. 파일 AES 암호화 → 임시 파일 생성
        from crypto_utils import encrypt_file_aes
        encrypted_path = os.path.join(FILES_DIR, "temp_encrypted.bin")
        encrypt_file_aes(self.aes_key, path, encrypted_path)

        # 3. 암호화된 파일 데이터를 서버로 전송
        with open(encrypted_path, "rb") as f:
            while chunk := f.read(4096):
                self.client_socket.sendall(chunk)

        # 4. 전송 후 임시 암호문 파일 삭제
        os.remove(encrypted_path)

        # 5. 파일 전송 종료 신호
        self.client_socket.send(encrypt_message_aes(self.aes_key, "__FILE_END__"))
        # 6. 전송 완성 메시지 
        self.chat_area.add_bubble(f"📁 파일 전송 완료: {filename}", "right")





if __name__ == "__main__":
    ClientUI().mainloop()
