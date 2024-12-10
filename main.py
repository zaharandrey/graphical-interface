from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature

# Генерація пари ключів RSA (приватного та публічного)
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

# Серіалізація ключів
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Запис ключів у файли
with open('private_key.pem', 'wb') as f:
    f.write(private_pem)
with open('public_key.pem', 'wb') as f:
    f.write(public_pem)

# Шифрування файлу за допомогою публічного ключа
def encrypt_file(file_path, public_key):
    with open(file_path, 'r', encoding='utf-8') as f:
        data = f.read()
    encrypted_data = public_key.encrypt(
        data.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    with open(f'encrypted_{file_path}', 'wb') as f:
        f.write(encrypted_data)

# Дешифрування файлу за допомогою приватного ключа
def decrypt_file(file_path, private_key):
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    with open(f'decrypted_{file_path}', 'w', encoding='utf-8') as f:
        f.write(decrypted_data.decode('utf-8'))

# Створення цифрового підпису файлу з використанням приватного ключа
def sign_file(file_path, private_key):
    with open(file_path, 'r', encoding='utf-8') as f:
        data = f.read()
    signature = private_key.sign(
        data.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    with open(f'signature_{file_path}', 'wb') as f:
        f.write(signature)

# Перевірка підпису за допомогою публічного ключа
def verify_signature(file_path, signature_path, public_key):
    with open(file_path, 'r', encoding='utf-8') as f:
        data = f.read()
    with open(signature_path, 'rb') as f:
        signature = f.read()
    try:
        public_key.verify(
            signature,
            data.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Signature is valid.")
    except InvalidSignature:
        print("Signature is invalid.")

# Використання функцій
encrypt_file('data.txt', public_key)
decrypt_file('encrypted_data.txt', private_key)
sign_file('data.txt', private_key)
verify_signature('data.txt', 'signature_data.txt', public_key)
