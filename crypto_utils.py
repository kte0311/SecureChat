from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import os



# AES (대칭키)관련 함수

def generate_aes_key():
    """16바이트(128비트) AES 키 생성"""
    return os.urandom(16)


def encrypt_message_aes(aes_key, plaintext):
    """AES 키로 평문 암호화"""

    # 1. AES-CBC용 16바이트 IV 생성
    iv = os.urandom(16)  
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # 2. 패딩 추가 (AES는 16바이트 단위로 암호화하므로)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    # 3. 암호화 수행
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext  # IV를 앞에 붙여 함께 전송


def decrypt_message_aes(aes_key, data):
    """AES 키로 암호문 복호화"""
    iv = data[:16]     # 1. 암호화할 때 생성된 16바이트 IV
    ciphertext = data[16:]     # 2. 실제 암호문
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    # 3. AES-CBC 복호화 수행
    padded_plain = decryptor.update(ciphertext) + decryptor.finalize()

    # 4. PKCS7 패딩 제거
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plain) + unpadder.finalize()

    # 5. 복호화 결과 반환
    return plaintext.decode()




# RSA (비대칭키) 관련 함수

def rsa_encrypt(public_key_pem, data):
    """RSA 공개키로 AES 키 암호화"""

    # 1. PEM 형식의 공개키를 로드하여 RSA 객체로 변환
    public_key = serialization.load_pem_public_key(public_key_pem)

    # 2. OAEP 패딩을 적용한 RSA 암호화 수행
    encrypted = public_key.encrypt(
        data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),    # 마스크 생성 함수(MGF1)
            algorithm=hashes.SHA256(),     # OAEP 내부 해시 알고리즘
            label=None
        )
    )
    return encrypted


def rsa_decrypt(private_key_pem, encrypted_data):
    """RSA 개인키로 AES 키 복호화"""

    # 1. PEM 형식의 개인키를 로드하여 RSA 객체로 변환
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    
    # 2. OAEP 패딩을 적용한 RSA 복호화 수행
    decrypted = private_key.decrypt(
        encrypted_data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted



# AES 파일 암호화 / 복호화

def encrypt_file_aes(aes_key, input_path, output_path):
    """파일을 AES로 암호화"""

    iv = os.urandom(16)     # 1. 랜덤 IV 생성
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # 2. 원본 파일을 읽기
    with open(input_path, "rb") as f:
        plaintext = f.read()


    # 3. 블록 단위 맞춤을 위한 PKCS7 패딩
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    # 4. AES 암호화 수행
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # 5. [IV + 암호문] 형태로 결과 저장
    with open(output_path, "wb") as f:
        f.write(iv + ciphertext)      # 16B IV + 암호문 저장


def decrypt_file_aes(aes_key, input_path, output_path):
    """암호화된 파일 복호화"""

    # 1. 파일을 바이너리로 읽어 IV와 암호문을 분리
    with open(input_path, "rb") as f:
        data = f.read()

    iv = data[:16]     # 암호화 시 사용한 IV
    ciphertext = data[16:]     # 실제 암호문 데이터

    # 2. AES-CBC 복호화 수행
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # 3. PKCS7 언패딩 수행 (블록 패딩 제거)
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    # 4. 복호화된 평문 데이터를 새로운 파일로 저장
    with open(output_path, "wb") as f:
        f.write(plaintext)
