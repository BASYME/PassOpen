__version__ = "0.7.0"


import sys
import json
import os
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QListWidget,
    QInputDialog, QLineEdit, QMessageBox, QListWidgetItem, QHBoxLayout, QLabel, QMenu,
    QDialog, QDialogButtonBox, QVBoxLayout, QLineEdit, QFormLayout,
    QFileDialog, QCheckBox, QTextEdit
)
from PySide6.QtCore import Qt, QRunnable, QThreadPool, Signal, QObject
from PySide6.QtGui import QIcon, QFontMetrics, QPixmap
from urllib.request import urlopen
from service_domain import SERVICE_DOMAIN_MAP
from password_generator import PasswordGeneratorDialog
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken
import base64
import csv
import qdarkstyle
import webbrowser

class FaviconSignalEmitter(QObject):
    finished = Signal(QPixmap, int)

FAVICON_CACHE = {}
THREADPOOL = QThreadPool()

    # --- Получение икноки сервиса ---
def get_favicon_pixmap(account):
        name = account.get("name", "").lower()
        for key, domain in SERVICE_DOMAIN_MAP.items():
            if key in name:
                try:
                   favicon_url = f"https://www.google.com/s2/favicons?sz=64&domain={domain}"
                   data = urlopen(favicon_url, timeout=2).read()
                   pixmap =QPixmap()
                   pixmap.loadFromData(data)
                   pixmap = pixmap.scaled(24, 24, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                   FAVICON_CACHE[domain] = pixmap
                   return pixmap
                except Exception:
                    break
        return QPixmap() # Пусто


class FaviconLoaderRunnable(QRunnable):
    def __init__(self, account, index, emitter):
        super().__init__()
        self.account = account
        self.index = index
        self.emitter = emitter
    def run(self):
        pixmap = get_favicon_pixmap(self.account)
        self.emitter.finished.emit(pixmap, self.index)

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
        def __init__(self, name='', username='', password='', favorite=False, note='', tags=None, url=''):
            super().__init__()
            self.setWindowTitle("Добавить запись")
            self.setMinimumWidth(300)

            layout = QVBoxLayout()

            self.name_edit = QLineEdit(name)
            self.username_edit = QLineEdit(username)



            pass_layout = QHBoxLayout()

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

            # --- URL ---
            self.url_edit = QLineEdit(url)
            self.url_edit.setPlaceholderText("URL сервиса")

            # --- Избранное ---
            self.favorite_checkbox = QCheckBox("⭐Избранное")
            self.favorite_checkbox.setChecked(favorite)
            # --- Заметка ---
            self.note_edit = QTextEdit(note)
            self.note_edit.setPlaceholderText("Заметка...")
            layout.addWidget(QLabel("Заметека:"))
            layout.addWidget(self.note_edit)
            # --- Тэги ---
            self.tags_edit = QLineEdit(", ".join(tags) if tags else "")
            self.tags_edit.setPlaceholderText("Тэги (через запятую)")
            # --- Поля ввода ---
            layout.addWidget(QLabel("Название сервиса:"))
            layout.addWidget(self.name_edit)
            layout.addWidget(QLabel("Имя пользователя:"))
            layout.addWidget(self.username_edit)
            layout.addWidget(QLabel("URL сервиса:"))
            layout.addWidget(self.url_edit)
            layout.addWidget(QLabel("Пароль:"))
            layout.addLayout(pass_layout)
            layout.addWidget(QLabel("Тэги:"))
            layout.addWidget(self.tags_edit)

            # --- Генерация пароля ---
            btn_generate = QPushButton("Расширенный генератор")
            btn_generate.clicked.connect(self.open_password_generator)
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

        def open_password_generator(self):
            dialog = PasswordGeneratorDialog(self)
            if dialog.exec() == QDialog.Accepted:
                password = dialog.get_password()
                if password:
                    self.password_edit.setText(password)

        def generate_password(self):
                import secrets
                import string
                chars = string.ascii_letters + string.digits + string.punctuation
                pdw = ''.join(secrets.choice(chars) for _ in range(16))
                self.password_edit.setText(pdw)

        def get_data(self):
                tags_str = self.tags_edit.text()
                tags = [tag.strip() for tag in tags_str.split(",") if tag.strip()]
                return {
                    "name": self.name_edit.text(),
                    "username": self.username_edit.text(),
                    "password": self.password_edit.text(),
                    "favorite": self.favorite_checkbox.isChecked(),
                    "note": self.note_edit.toPlainText(),
                    "tags": tags,
                    "url": self.url_edit.text()
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
        self.is_dark = False # Темная тема
        super().__init__()
        self.setWindowIcon(QIcon("logo.png"))
        self.setWindowTitle("OpenPass — Простой менеджер паролей")
        self.setGeometry(200, 200, 400, 400)
        self.key = key
        self.vault = load_vault(self.key)
        
        self.layout = QVBoxLayout()
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(0)
        # --- Строка поиска ---
        search_layout = QHBoxLayout()
        self.search_icon = QLabel("🔍")
        self.search_icon.setFixedWidth(24)
        search_layout.addWidget(self.search_icon)
        # --- Кнопка смены темы ---
        self.theme_button = QPushButton("🌙")
        self.theme_button.setFixedWidth(32)
        self.theme_button.clicked.connect(self.toggle_theme)
        search_layout.addWidget(self.theme_button)

        self.search_field = QLineEdit()
        self.search_field.setPlaceholderText("Поиск...")
        self.search_field.textChanged.connect(self.refresh_list)
        search_layout.addWidget(self.search_field)

        self.layout.addLayout(search_layout)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(0)

        self.list_widget = QListWidget()
        self.list_widget.setMinimumHeight(200)
        self.layout.addWidget(self.list_widget)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(0)
        self.add_button = QPushButton("Добавить запись")
        self.add_button.setObjectName("add-btn")
        self.export_button = QPushButton("Экспорт")
        self.import_button = QPushButton("Импорт")
        self.about_button = QPushButton("О программе")
        self.lock_button = QPushButton("🔒 Блокировать")
        


        buttons_layout = QHBoxLayout()
        buttons_layout.addWidget(self.add_button)
        buttons_layout.addWidget(self.export_button)
        buttons_layout.addWidget(self.import_button)
        buttons_layout.addWidget(self.about_button)
        buttons_layout.addWidget(self.lock_button)
        self.layout.addLayout(buttons_layout)

        self.add_button.clicked.connect(self.add_entry)
        self.export_button.clicked.connect(self.export_csv)
        self.import_button.clicked.connect(self.import_csv)
        self.about_button.clicked.connect(self.show_about)
        self.lock_button.clicked.connect(self.lock_app)

        self.setLayout(self.layout)
        self.refresh_list()

    # ----- Блокировка/разблокировка -----
    def lock_app(self):
        self.hide()
        salt = get_or_create_salt()
        while True:
            pw, ok = QInputDialog.getText(None, "Разблокировка", "Введите мастер-пароль:", QLineEdit.Password)
            if not ok:
                QApplication.quit()
                return
            key = derive_key(pw, salt)
            try:
                vault_exists = os.path.exists(VAULT_FILE)
                data = load_vault(key)
                if vault_exists and not data["accounts"]:
                    raise InvalidToken()
                self.key = key
                break
            except InvalidToken:
                QMessageBox.critical(None, "Ошибка", "Неверный мастер-пароль!")
    # Показываем окно обратно
        self.show()
        self.refresh_list()
            
    # ----- О программе -----
    def show_about(self):
        QMessageBox.information(
            self,
            "О программе",
            "OpenPass — Простой менеджер паролей\n\n"
            f"PassOpen {__version__}\n"
            "Автор: BASYME\n"
            "Лицензия: MIT"
            "GitHub: https://github.com/BASYME/PassOpen\n"
        )
        
        
    # ----- Смена темы -----
    def set_dark_theme(self):
        import qdarkstyle
        QApplication.instance().setStyleSheet(qdarkstyle.load_stylesheet_pyside6())
        self.theme_button.setText("☀️")
        self.is_dark = True

    def set_light_theme(self):
        QApplication.instance().setStyleSheet("")
        self.theme_button.setText("🌙")
        self.is_dark = False

    def toggle_theme(self):
        if not self.is_dark:
            self.set_dark_theme()
        else:
            self.set_light_theme()


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
        # --- Сортировка по избранному ---
        accounts_sorted = sorted(
            self.vault["accounts"],
            key=lambda acc: acc.get("favorite", False),
            reverse=True
        )
        for acc in accounts_sorted:
            origin_index = self.vault["accounts"].index(acc)
            tags = acc.get("tags", [])
            if query in acc["name"].lower() or query in acc["username"].lower() or any(query in tag.lower() for tag in tags):
                widget = AccountWidget(acc, self, origin_index)
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
        dialog = AddEditDialog(acc["name"], acc["username"], acc["password"], acc.get("favorite", False), acc.get("note", ""), acc.get("tags", []), acc.get("url", ""))
        if dialog.exec() == QDialog.Accepted:
            data = dialog.get_data()
            self.vault["accounts"][index] = data
            save_vault(self.vault, self.key)
            self.refresh_list()






# ----- Виджет для отображения и редактирования записи -----

class AccountWidget(QWidget):

    def __init__(self, account, parent, index):



        super().__init__()
        self.setObjectName("card")
        self.account = account
        self.index = index
        self.parent = parent

        layout = QHBoxLayout(self)
        layout.setContentsMargins(5, 2, 5, 2)
        layout.setAlignment(Qt.AlignVCenter)

        

        # --- Тэги ---
        tags = account.get("tags", [])
        if tags:
            tags_layout = QHBoxLayout()
            tags_layout.setSpacing(6)
            tags_layout.setContentsMargins(0, 0, 0, 0)
            tags_layout.setSpacing(6)
            for tag in tags:
                tag_chip = QLabel(tag)
                tag_chip.setObjectName("chip")
                tags_layout.addWidget(tag_chip)
            layout.addLayout(tags_layout)
            

        self.icon_label = QLabel()
        self.icon_label.setFixedSize(26, 26)
        layout.addWidget(self.icon_label)
         # --- Иконка сервиса ---       
        pixmap = get_favicon_pixmap(self.account)
        if not pixmap.isNull():
            self.icon_label.setPixmap(pixmap)
        else:
            self.emitter = FaviconSignalEmitter()
            self.emitter.finished.connect(self.on_favicon_loaded)
            THREADPOOL.start(FaviconLoaderRunnable(self.account, self.index, self.emitter))

        # --- Звезда избранного ---
        if account.get("favorite", False):
            star = QLabel("⭐")
            star.setFixedWidth(22)
            layout.addWidget(star)

        # --- Форматирование текста ---
        full_text = f"{account['name']} ({account['username']})".strip()
        metric = QFontMetrics(self.font())
        max_width = 300
        elided_text = metric.elidedText(full_text, Qt.ElideRight, max_width)
        label = QLabel(elided_text)
        label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(label, stretch=1)

        # --- URL ---
        url = account.get("url", "")
        if url:
            open_btn = QPushButton("🔗")
            open_btn.setToolTip("Открыть сайт")
            open_btn.setFixedSize(22, 22)
            open_btn.setStyleSheet("border: none;")
            open_btn.clicked.connect(lambda _, url=url: webbrowser.open(url))
            layout.addWidget(open_btn)

         # --- Заметка ---
        note = account.get("note", "")
        if note:
            label.setToolTip(note)

        btn = QPushButton("⋮")
        btn.setFixedWidth(40)
        btn.setFlat(True)
        btn.setStyleSheet("font-size: 18px;")
        layout.addWidget(btn, alignment=Qt.AlignRight)

        menu = QMenu(self)
        action_copy = menu.addAction("Копировать пароль")
        action_edit = menu.addAction("Редактировать")
        action_delete = menu.addAction("Удалить")
        # --- Избранное ---
        if self.account.get("favorite", False):
            action_favorite = menu.addAction("Удалить из избранного")
        else:
            action_favorite = menu.addAction("Добавить в избранное")

        def show_menu():
            menu.exec(btn.mapToGlobal(btn.rect().bottomRight()))
        btn.clicked.connect(show_menu)

        action_copy.triggered.connect(lambda: self.parent.copy_password(self.index))
        action_edit.triggered.connect(lambda: self.parent.edit_entry(self.index))
        action_delete.triggered.connect(lambda: self.parent.delete_entry(self.index))
        action_favorite.triggered.connect(lambda: self.toggle_favorite())
    
    def toggle_favorite(self):
        self.account["favorite"] = not self.account.get("favorite", False)
        self.parent.vault["accounts"][self.index]["favorite"] = self.account["favorite"]
        save_vault(self.parent.vault, self.parent.key)
        self.parent.refresh_list()

        
    def on_favicon_loaded(self,pixmap, index):
        if index == self.index and not pixmap.isNull():
            name = self.account.get("name", "").lower()
            for key, domain in SERVICE_DOMAIN_MAP.items():
                if key in name:
                    if domain not in FAVICON_CACHE:
                        FAVICON_CACHE[domain] = pixmap
            self.icon_label.setPixmap(pixmap)
        
        




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
    
    # --- Загрузка стилей ---
    with open("style.qss", "r", encoding="utf-8") as f:
        app.setStyleSheet(f.read())
    # Ввод мастер-пароля
    salt = get_or_create_salt()
    vault_exists = os.path.exists(VAULT_FILE)
    
    while True:
        pw, ok = QInputDialog.getText(None, "Мастер-пароль", "Введите мастер-пароль:", QLineEdit.Password)
        if not ok:
            sys.exit()
        key = derive_key(pw, salt)
        try:
            data = load_vault(key)
            if vault_exists and not data["accounts"]:
                raise InvalidToken()
            break
        except InvalidToken:
            QMessageBox.critical(None, "Ошибка", "Неверный мастер-пароль.")
    try:
        window = MainWindow(key)
        window.show()
        app.exec()
    except InvalidToken:
        QMessageBox.critical(None, "Ошибка", "Неверный мастер-пароль.")
        sys.exit()

   

if __name__ == "__main__":
    main()
