__version__ = "0.3.0"


import sys
import json
import os
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QListWidget,
    QInputDialog, QLineEdit, QMessageBox, QListWidgetItem, QHBoxLayout, QLabel, QMenu,
    QDialog, QDialogButtonBox, QVBoxLayout, QLineEdit, QFormLayout
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon
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
    


# ----- Диалог добавления/редактирования записи -----
class AddEditDialog(QDialog):
        def __init__(self, name='', username='', password=''):
            super().__init__()
            self.setWindowTitle("Добавить запись")
            self.setMinimumWidth(300)

            layout = QVBoxLayout()

            self.name_edit = QLineEdit(name)
            self.username_edit = QLineEdit(username)
            
            # --- Пароль ---
            pass_layout = QHBoxLayout()
            self.password_edit = QLineEdit(password)
            self.password_edit.setEchoMode(QLineEdit.Password)
            pass_layout.addWidget(self.password_edit)
            self.toggle_btn = QPushButton("👁")
            self.toggle_btn.setCheckable(True)
            self.toggle_btn.setFixedWidth(32)
            self.toggle_btn.clicked.connect(self.toggle_password)
            pass_layout.addWidget(self.toggle_btn)
            # --- Поля ввода ---
            layout.addWidget(QLabel("Название сервиса:"))
            layout.addWidget(self.name_edit)
            layout.addWidget(QLabel("Имя пользователя:"))
            layout.addWidget(self.username_edit)
            layout.addWidget(QLabel("Пароль:"))
            layout.addLayout(pass_layout)

            # --- Генерация пароля ---
            btn_generate = QPushButton("Сгенерировать пароль")
            btn_generate.clicked.connect(self.generate_password)
            layout.addWidget(btn_generate)

            buttons = QHBoxLayout()
            btn_ok = QPushButton("OK")
            btn_cancel = QPushButton("Отмена")
            btn_ok.clicked.connect(self.accept)
            btn_cancel.clicked.connect(self.reject)
            buttons.addWidget(btn_ok)
            buttons.addWidget(btn_cancel)
            layout.addLayout(buttons)

            self.setLayout(layout)

        def generate_password(self):
                import secrets
                import string
                chars = string.ascii_letters + string.digits + string.punctuation
                pdw = ''.join(secrets.choice(chars) for _ in range(16))
                self.password_edit.setText(pdw)

        def get_data(self):
                return {
                    "name": self.name_edit.text(),
                    "username": self.username_edit.text(),
                    "password": self.password_edit.text()
                }
        def toggle_password(self):
            if self.toggle_btn.isChecked():
                self.password_edit.setEchoMode(QLineEdit.Normal)
                self.toggle_btn.setText("🙈")
            else:
                self.password_edit.setEchoMode(QLineEdit.Password)
                self.toggle_btn.setText("👁")



# ----- Главное окно -----
class MainWindow(QWidget):
    def __init__(self, key):
        super().__init__()
        self.setWindowIcon(QIcon("logo.png"))
        self.setWindowTitle("OpenPass — Простой менеджер паролей")
        self.setGeometry(200, 200, 400, 400)
        self.key = key
        self.vault = load_vault(self.key)
        
        self.layout = QVBoxLayout()
        # --- Строка поиска ---
        search_layout = QHBoxLayout()
        self.search_icon = QLabel("🔍")
        self.search_icon.setFixedWidth(24)
        search_layout.addWidget(self.search_icon)

        self.search_field = QLineEdit()
        self.search_field.setPlaceholderText("Поиск...")
        self.search_field.textChanged.connect(self.refresh_list)
        search_layout.addWidget(self.search_field)

        self.layout.addLayout(search_layout)

        self.list_widget = QListWidget()
        self.add_button = QPushButton("Добавить запись")
        self.add_button.clicked.connect(self.add_entry)

        self.layout.addWidget(self.list_widget)
        self.layout.addWidget(self.add_button)
        self.setLayout(self.layout)

        self.refresh_list()

    def add_entry(self):
        dialog = AddEditDialog()
        if dialog.exec() == QDialog.Accepted:
            data = dialog.get_data()
            if not data["name"] or not data["username"] or not data["password"]:
                QMessageBox.warning(self, "Ошибка", "Все поля должны быть заполнены.")
                return
            self.vault["accounts"].append(data)
            save_vault(self.vault, self.key)
            self.refresh_list()

                


    def refresh_list(self):
        self.list_widget.clear()
        query = self.search_field.text().lower() if hasattr(self, 'search_field') else ""
        for idx, acc in enumerate(self.vault["accounts"]):
            if (
                query in acc["name"].lower() or
                query in acc["username"].lower()
            ):
                widget = AccountWidget(acc, self, idx)
                item = QListWidgetItem(self.list_widget)
                item.setSizeHint(widget.sizeHint())
                self.list_widget.addItem(item)
                self.list_widget.setItemWidget(item, widget)
        


    # ----- Копирование пароля в буфер обмена -----
    def copy_password(self, index):
        password = self.vault["accounts"][index]["password"]
        QApplication.clipboard().setText(password)
        QMessageBox.information(self, "PassOpen", "Пароль скопирован в буфер обмена.")

    def delete_entry(self, index):
        reply = QMessageBox.question(self, "Удаление", "Вы уверены, что хотите удалить эту запись?", QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            del self.vault["accounts"][index]
            save_vault(self.vault, self.key)
            self.refresh_list()

    def edit_entry(self, index):
        acc = self.vault["accounts"][index]
        dialog = AddEditDialog(acc["name"], acc["username"], acc["password"])
        if dialog.exec() == QDialog.Accepted:
            data = dialog.get_data()
            self.vault["accounts"][index] = {
                "name": data["name"],
                "username": data["username"],
                "password": data["password"]
            }
            save_vault(self.vault, self.key)
            self.refresh_list()






# ----- Виджет для отображения и редактирования записи -----

class AccountWidget(QWidget):
    def __init__(self, account, parent, index):
        super().__init__()
        self.account = account
        self.index = index
        self.parent = parent

        layout = QHBoxLayout(self)
        layout.setContentsMargins(5, 2, 5, 2)
        layout.setAlignment(Qt.AlignVCenter)


        label = QLabel(f"{account['name']} ({account['username']})")
        layout.addWidget(label)

        btn = QPushButton("⋮")
        btn.setFixedWidth(40)
        btn.setFlat(True)
        btn.setStyleSheet("font-size: 18px;")
        layout.addWidget(btn, alignment=Qt.AlignRight)

        menu = QMenu(self)
        action_copy = menu.addAction("Копировать пароль")
        action_edit = menu.addAction("Редактировать")
        action_delete = menu.addAction("Удалить")

        def show_menu():
            menu.exec(btn.mapToGlobal(btn.rect().bottomRight()))
        btn.clicked.connect(show_menu)

        action_copy.triggered.connect(lambda: self.parent.copy_password(self.index))
        action_edit.triggered.connect(lambda: self.parent.edit_entry(self.index))
        action_delete.triggered.connect(lambda: self.parent.delete_entry(self.index))
        
        




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
    app.setWindowIcon(QIcon("logo.png"))
    
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
