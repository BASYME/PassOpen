from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QSlider,
    QCheckBox, QPushButton, QLineEdit, QMessageBox
)
from PySide6.QtCore import Qt

import secrets
import string

class PasswordGeneratorDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Генератор пароля")
        self.setMinimumWidth(350)
        layout = QVBoxLayout(self)

        self.length_label = QLabel()
        layout.addWidget(self.length_label)
        # --- Длина пароля ---
        self.length_slider = QSlider(Qt.Horizontal)
        self.length_slider.setMinimum(6)
        self.length_slider.setMaximum(40)
        self.length_slider.setValue(16)
        self.length_slider.setTickInterval(1)
        self.length_slider.valueChanged.connect(self.update_length_label)

        layout.addWidget(self.length_slider)
        self.update_length_label(self.length_slider.value())

        # --- Опции генерации ---
        self.letters_cb = QCheckBox("Буквы (a-z, A-Z)")
        self.letters_cb.setChecked(True)
        self.digits_cb = QCheckBox("Цифры (0-9)")
        self.digits_cb.setChecked(True)
        self.symbols_cb = QCheckBox("Спецсимволы (!@#$%^&*()_+)")
        self.symbols_cb.setChecked(True)
        self.exclude_similar_cb = QCheckBox("Исключить похожие символы (O0Il1)")
        self.exclude_similar_cb.setChecked(True)
        layout.addWidget(self.letters_cb)
        layout.addWidget(self.digits_cb)
        layout.addWidget(self.symbols_cb)
        layout.addWidget(self.exclude_similar_cb)

        # --- Результат генерации ---
        self.result_label = QLineEdit()
        self.result_label.setReadOnly(True)
        layout.addWidget(self.result_label)

        # --- Кнопки ---
        btns = QHBoxLayout()
        self.generate_btn = QPushButton("Сгенерировать")
        self.generate_btn.clicked.connect(self.generate_password)
        self.ok_btn = QPushButton("OK")
        self.ok_btn.clicked.connect(self.accept)
        btns.addWidget(self.generate_btn)
        btns.addWidget(self.ok_btn)
        layout.addLayout(btns)

        self.generate_password()
       
    def update_length_label(self, val):
        self.length_label.setText(f"Длина пароля: {val}")


    def generate_password(self):
        length = self.length_slider.value()
        chars = ""
        if self.letters_cb.isChecked():
            chars += string.ascii_letters
        if self.digits_cb.isChecked():
            chars += string.digits
        if self.symbols_cb.isChecked():
            chars += string.punctuation
        if self.exclude_similar_cb.isChecked():
            for ch in "O0Il1":
                chars = chars.replace(ch, "")
        if not chars:
            QMessageBox.warning(self, "Ошибка", "Необходимо выбрать хотя бы один тип символов.")
            return
        password = ''.join(secrets.choice(chars) for _ in range(length))
        self.result_label.setText(password)


    def get_password(self):
        return self.result_label.text()
     

        # --- Поле для пароля ---
        