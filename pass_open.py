import sys
import json
import os
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QListWidget,
    QInputDialog, QLineEdit, QMessageBox
)
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken
import base64

# ----- Криптоутилиты -----
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return base64.urlsafe_b64encode(key)

def get_salt():
    return os.urandom(16)

VAULT_FILE = "vault.dat"
SALT_FILE = "vault.salt"

# ----- Логика хранения -----
def save_vault(data, key):
    f = Fernet(key)
    enc = f.encrypt(json.dumps(data).encode())
    with open(VAULT_FILE, 'wb') as file:
        file.write(enc)

def load_vault(key):
    f = Fernet(key)
    try:
        with open(VAULT_FILE, 'rb') as file:
            enc = file.read()
        return json.loads(f.decrypt(enc).decode())
    except (FileNotFoundError, InvalidToken):
        return {"accounts": []}

# ----- Главное окно -----
class MainWindow(QWidget):
    def __init__(self, key):
        super().__init__()
        self.setWindowTitle("OpenPass — Простой менеджер паролей")
        self.setGeometry(200, 200, 400, 400)
        self.key = key
        self.vault = load_vault(self.key)
        
        self.layout = QVBoxLayout()
        self.list_widget = QListWidget()
        self.add_button = QPushButton("Добавить запись")
        self.add_button.clicked.connect(self.add_entry)

        self.layout.addWidget(self.list_widget)
        self.layout.addWidget(self.add_button)
        self.setLayout(self.layout)

        self.refresh_list()

    def refresh_list(self):
        self.list_widget.clear()
        for acc in self.vault["accounts"]:
            self.list_widget.addItem(f"{acc['name']} ({acc['username']})")

    def add_entry(self):
        name, ok1 = QInputDialog.getText(self, "Название сервиса", "Введите название:")
        if not ok1 or not name: return
        username, ok2 = QInputDialog.getText(self, "Имя пользователя", "Введите логин/имя:")
        if not ok2 or not username: return
        password, ok3 = QInputDialog.getText(self, "Пароль", "Введите пароль:", QLineEdit.Password)
        if not ok3 or not password: return

        self.vault["accounts"].append({"name": name, "username": username, "password": password})
        save_vault(self.vault, self.key)
        self.refresh_list()

# ----- Стартовая точка -----
def get_or_create_salt():
    if os.path.exists(SALT_FILE):
        with open(SALT_FILE, 'rb') as f:
            return f.read()
    else:
        salt = get_salt()
        with open(SALT_FILE, 'wb') as f:
            f.write(salt)
        return salt

def main():
    app = QApplication(sys.argv)
    
    # Ввод мастер-пароля
    salt = get_or_create_salt()
    pw, ok = QInputDialog.getText(None, "Мастер-пароль", "Введите мастер-пароль:", QLineEdit.Password)
    if not ok or not pw:
        sys.exit()
    key = derive_key(pw, salt)
    
    try:
        window = MainWindow(key)
        window.show()
        app.exec()
    except InvalidToken:
        QMessageBox.critical(None, "Ошибка", "Неверный мастер-пароль или поврежден файл базы.")
        sys.exit()

if __name__ == "__main__":
    main()
