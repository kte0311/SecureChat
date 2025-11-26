from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os

# RSA 키 파일이 저장될 폴더명
KEY_FOLDER = "keys"

def generate_rsa_key_pair(name: str):
    """RSA 공개키/개인키 쌍 생성 및 파일 저장"""

    # 1. 키 저장 폴더가 없으면 생성
    if not os.path.exists(KEY_FOLDER):
        os.makedirs(KEY_FOLDER)

    # 2. RSA 개인키(Private Key) 생성
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # 3. 개인키로부터 공개키(Public Key) 생성
    public_key = private_key.public_key()

    # 4. 개인키(Private key) 저장
    with open(f"{KEY_FOLDER}/{name}_private.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # 5. 공개키 저장 (SubjectPublicKeyInfo 형식)
    with open(f"{KEY_FOLDER}/{name}_public.pem", "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    # 6. 완료 메시지 출력
    print(f"[+] RSA 키쌍 생성 완료 → {KEY_FOLDER}/{name}_*.pem")



def load_public_key(path: str):
    """공개키 로드"""
    with open(path, "rb") as f:
        return f.read()

def load_private_key(path: str):
    """개인키 로드"""
    with open(path, "rb") as f:
        return f.read()
