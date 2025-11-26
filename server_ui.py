import tkinter as tk
import threading, socket, os
from key_utils import load_public_key, load_private_key
from crypto_utils import rsa_decrypt, decrypt_message_aes, encrypt_message_aes, decrypt_file_aes

# 파일 저장 경로 설정
BASE_DIR = "files"
FILES_DIR = os.path.join(BASE_DIR, "received")
os.makedirs(FILES_DIR, exist_ok=True)


# 말풍선 클래스 (채팅 메시지를 말풍선 형태로 출력)
class ChatBubble(tk.Frame):
    def __init__(self, master, text, side="left", color="#F1F0F0", text_color="#000"):
        super().__init__(master, bg=master["bg"])
        label = tk.Label(
            self, text=text, bg=color, fg=text_color,
            wraplength=320,
            justify="left" if side == "left" else "right",
            font=("Arial", 11), padx=10, pady=6, bd=0, relief="solid"
        )
        label.pack(anchor="w" if side == "left" else "e")


# 채팅 영역 클래스 (스크롤 가능한 메시지 표시 구역)
class ChatArea(tk.Frame):
    def __init__(self, master, bg):
        super().__init__(master, bg=bg)

        # Canvas + Scrollbar 구조, 메시지 스크롤 가능
        self.canvas = tk.Canvas(self, bg=bg, highlightthickness=0)
        self.scrollbar = tk.Scrollbar(self, command=self.canvas.yview)
        self.scrollable_frame = tk.Frame(self.canvas, bg=bg)
        self.window_id = self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")

        # 프레임 크기가 변경될 때 스크롤 영역 자동 조정
        self.scrollable_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfig(self.window_id, width=e.width))
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    # 일반 채팅 메시지 추가 (좌/우 정렬)
    def add_bubble(self, text, side="left"):
        color = "#C8FACC" if side == "right" else "#F1F0F0"   # 서버는 초록색 계열
        text_color = "#004B23" if side == "right" else "#000"
        line = tk.Frame(self.scrollable_frame, bg=self.scrollable_frame["bg"])
        line.pack(fill="x", pady=3)
        bubble = ChatBubble(line, text, side, color, text_color)
        bubble.pack(side="right" if side == "right" else "left",
                    padx=(50, 10) if side == "right" else (10, 50))
        self.canvas.update_idletasks()
        self.canvas.yview_moveto(1)

    # 시스템 메시지 (상태나 로그 표시)
    def add_system_message(self, text):
        lbl = tk.Label(self.scrollable_frame, text=text, bg=self.scrollable_frame["bg"],
                       fg="#777", font=("Arial", 10, "italic"))
        lbl.pack(anchor="center", pady=3)
        self.canvas.update_idletasks()
        self.canvas.yview_moveto(1)


# 서버 UI 메인 클래스
class ServerUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("💚 Server - Secure Chat")
        self.geometry("520x640")
        self.configure(bg="#E9F7EF")

        # 클라이언트 연결 객체 및 AES 키 저장용 변수
        self.conn = None
        self.aes_key = None

        # 상단 헤더 (서버 상태 표시)
        header = tk.Frame(self, bg="#2E8B57", height=50)
        header.pack(fill=tk.X)
        tk.Label(header, text="SERVER", bg="#2E8B57", fg="white",
                 font=("Arial", 15, "bold")).pack(side=tk.LEFT, padx=15)
        self.status_label = tk.Label(header, text="Listening...", bg="#2E8B57", fg="white", font=("Arial", 11))
        self.status_label.pack(side=tk.RIGHT, padx=15)

        # 채팅 출력 영역
        self.chat_area = ChatArea(self, "#FDFDFD")
        self.chat_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # 하단 메시지 입력 및 전송 버튼
        bottom = tk.Frame(self, bg="#E9F7EF")
        bottom.pack(fill=tk.X, pady=10)
        self.msg_entry = tk.Entry(bottom, font=("Arial", 12))
        self.msg_entry.pack(side=tk.LEFT, padx=10, pady=5, ipady=4, expand=True, fill=tk.X)
        tk.Button(bottom, text="Send", bg="#2E8B57", fg="white",
                  width=7, command=self.send_message).pack(side=tk.RIGHT, padx=10)

        # 서버 스레드 실행 (자동으로 start_server 실행)
        threading.Thread(target=self.start_server, daemon=True).start()


    # 서버 시작 및 클라이언트 연결 수락 + 키 교환 (RSA + AES)
    def start_server(self):
        try:
            # 1. 서버 공개키 / 개인키 로드
            server_pub = load_public_key("keys/server_public.pem")
            server_pri = load_private_key("keys/server_private.pem")

            # 2. 서버 소켓 생성 및 대기
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.bind(("0.0.0.0", 5000))
            server_socket.listen()
            self.chat_area.add_system_message("[Server] 포트 5000에서 연결 대기 중...")

            # 3. 클라이언트 연결 수락
            conn, addr = server_socket.accept()
            self.conn = conn
            self.status_label.config(text=f"Connected: {addr}")
            self.chat_area.add_system_message(f"[Server] {addr} 연결됨")

            # 4. RSA 공개키 교환
            conn.send(server_pub)
            client_pub = conn.recv(4096)
            encrypted_aes_key = conn.recv(512)

            # 5. 클라이언트로부터 수신된 AES 세션키 복호화
            self.aes_key = rsa_decrypt(server_pri, encrypted_aes_key)

            # 6. 키 정보 표시 (HEX, 길이 등)
            self.chat_area.add_system_message(f" RSA 공개키 길이: {len(server_pub)} bytes")
            self.chat_area.add_system_message(f" AES 세션키 길이: {len(self.aes_key)} bytes")
            self.chat_area.add_system_message(f" AES 세션키 (HEX): {self.aes_key.hex().upper()}")
            self.chat_area.add_system_message("✅ AES 세션키 수신 완료")

            # 7. 메시지 수신 루프 (AES 암호문 복호화)
            while True:
                enc_data = conn.recv(4096)
                if not enc_data:
                    break
                try:
                    msg = decrypt_message_aes(self.aes_key, enc_data)
                except Exception:
                    continue

                # 파일 전송 제어 신호 감지
                if msg == "__FILE_START__":
                    self.receive_file()
                    continue

                # 암호문 및 복호화 결과 출력
                cipher_hex = enc_data.hex().upper()
                self.chat_area.add_system_message(f"[수신 암호문] {cipher_hex[:80]}...")
                self.chat_area.add_bubble(f"[복호화 결과] {msg}", "left")

        except Exception as e:
            self.chat_area.add_system_message(f"[오류] {e}")


    # 파일 수신 및 복호화 함수
    def receive_file(self):
        try:
            # 1. 암호화된 파일명 수신 및 복호화
            enc_name = self.conn.recv(4096)
            filename = decrypt_message_aes(self.aes_key, enc_name)
            self.chat_area.add_system_message(f"[Server] 파일명 수신: {filename}")

            # 저장 경로 지정
            encrypted_path = os.path.join(FILES_DIR, f"{filename}_encrypted.bin")
            decrypted_path = os.path.join(FILES_DIR, f"{filename}_decrypted.txt")

            received_data = b""

            # 2. 파일 데이터 수신 루프
            while True:
                chunk = self.conn.recv(4096)
                if not chunk:
                    break

                # 제어 신호인지 검사 (파일 종료 신호)
                is_control = False
                try:
                    msg = decrypt_message_aes(self.aes_key, chunk)
                    if msg == "__FILE_END__":
                        is_control = True
                        break
                except Exception:
                    pass

                # 암호화된 파일 데이터 누적
                if not is_control:
                    received_data += chunk

            # 3. 암호문 저장
            if len(received_data) == 0:
                self.chat_area.add_system_message("⚠️ 수신된 파일 데이터가 없습니다.")
                return
            with open(encrypted_path, "wb") as f:
                f.write(received_data)
            self.chat_area.add_system_message(f" 암호문 저장 완료 → {encrypted_path}")

            # 4. AES 복호화 수행
            try:
                decrypt_file_aes(self.aes_key, encrypted_path, decrypted_path)
                self.chat_area.add_system_message(f" 복호화 저장 완료 → {decrypted_path}")
                self.chat_area.add_bubble(f"📂 파일 수신 완료: {filename}", "left")
            except Exception as e:
                self.chat_area.add_system_message(f"[오류] 복호화 실패: {e}")

        except Exception as e:
            import traceback
            traceback.print_exc()
            self.chat_area.add_system_message(f"[오류] 파일 수신 중 예외 발생: {e}")


    # 메시지 송신 함수 (서버 → 클라이언트)
    def send_message(self):
        msg = self.msg_entry.get().strip()
        if not msg or not self.conn:
            return

        # 1. AES 암호화 수행
        enc_msg = encrypt_message_aes(self.aes_key, msg)

        # 2. 암호문 전송
        self.conn.send(enc_msg)

        # 3. 암호문 및 평문 표시
        self.chat_area.add_system_message(f"[송신 암호문] {enc_msg.hex().upper()[:80]}...")
        self.chat_area.add_bubble(msg, "right")

        # 4. 입력창 초기화
        self.msg_entry.delete(0, tk.END)


# 프로그램 실행
if __name__ == "__main__":
    ServerUI().mainloop()
