__version__ = "0.4.0"


import sys
import json
import os
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QListWidget,
    QInputDialog, QLineEdit, QMessageBox, QListWidgetItem, QHBoxLayout, QLabel, QMenu,
    QDialog, QDialogButtonBox, QVBoxLayout, QLineEdit, QFormLayout,
    QFileDialog
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon, QFontMetrics
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken
import base64
import csv

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
        self.list_widget.setMinimumHeight(200)
        self.layout.addWidget(self.list_widget)
        self.add_button = QPushButton("Добавить запись")
        self.export_button = QPushButton("Экспорт")
        self.import_button = QPushButton("Импорт")

        buttons_layout = QHBoxLayout()
        buttons_layout.addWidget(self.add_button)
        buttons_layout.addWidget(self.export_button)
        buttons_layout.addWidget(self.import_button)
        self.layout.addLayout(buttons_layout)

        self.add_button.clicked.connect(self.add_entry)
        self.export_button.clicked.connect(self.export_csv)
        self.import_button.clicked.connect(self.import_csv)

        self.setLayout(self.layout)
        self.refresh_list()

    # ----- Экспорт в CSV -----
    def export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Экспорт в CSV", "", "CSV файлы (*.csv)")
        if not path:
            return
        with open(path, "w", newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=["name", "username", "password"])
            writer.writeheader()
            for acc in self.vault["accounts"]:
                writer.writerow({
                    "name": acc.get("name", ""),
                    "username": acc.get("username", ""),
                    "password": acc.get("password", "")
                })
        QMessageBox.information(self, "Экспорт", f"Данные успешно экспортированы в CSV")

    # ----- Импорт из CSV -----
    def import_csv(self):
        path, _ = QFileDialog.getOpenFileName(self, "Импорт из CSV", "", "CSV файлы (*.csv)")
        if not path:
            return
        imported = 0
        with open(path, "r", newline='', encoding='utf-8') as csvfile:

            first_line = csvfile.readline()
            csvfile.seek(0)

            if not any(x in first_line.lower() for x in ["name", "username", "password"]):
                reader = csv.DictReader(csvfile)
                for row in reader:
                    # Яндекс 0 - url 1 - login 2 - password
                    self.vault["accounts"].append({
                        "name": row["0"],
                        "username": row["1"],
                        "password": row["2"]
                    })
                    imported += 1
            else:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    username = row.get("username") or row.get("login") or ""
                    name = row.get("name") or row.get("url") or ""
                    password = row.get("password") or row.get("pass") or ""
                    if name and username and password:
                        self.vault["accounts"].append({
                            "name": name,
                            "username": username,
                            "password": password
                        })
                        imported += 1
        save_vault(self.vault, self.key)
        self.refresh_list()
        self.clean_vault()
        QMessageBox.information(self, "Импорт", f"Импортировано {imported} записей")
        
# --- Чистка базы от пустых строк ---
    def clean_vault(self):
        before = len(self.vault["accounts"])
        self.vault["accounts"] = [
            acc for acc in self.vault["accounts"]
            if acc.get("name") or acc.get("username") or acc.get("password")
        ]
        after = len(self.vault["accounts"])
        if after < before:
            save_vault(self.vault, self.key)
            self.refresh_list()
            QMessageBox.information(self, "Очистка", f"Удалено {before - after} пустых записей")



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

        # --- Форматирование текста ---
        full_text = f"{account['name']} ({account['username']})".strip()
        metric = QFontMetrics(self.font())
        max_width = 300
        elided_text = metric.elidedText(full_text, Qt.ElideRight, max_width)
        label = QLabel(elided_text)
        label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(label, stretch=1)

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
