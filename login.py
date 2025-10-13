
"""
Formulario de registro simple con:
- Campos: Nombre, Email, Contraseña (máscara opcional)
- Validación de email
- Validación de seguridad de contraseña
- Guardado en users.json con contraseña derivada (PBKDF2)
Requiere: Python 3.6+
"""

import json
import os
import re
import base64
import hashlib
import secrets
import tkinter as tk
from tkinter import messagebox

USERS_FILE = os.path.join(os.path.dirname(__file__), "users.json")


def is_valid_email(email: str) -> bool:
    return re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", email) is not None


def password_strength_info(pw: str) -> (bool, str):
    errors = []
    if len(pw) < 8:
        errors.append("mínimo 8 caracteres")
    if not re.search(r"[A-Z]", pw):
        errors.append("una letra mayúscula")
    if not re.search(r"[a-z]", pw):
        errors.append("una letra minúscula")
    if not re.search(r"\d", pw):
        errors.append("un dígito")
    if not re.search(r"[^\w\s]", pw):
        errors.append("un carácter especial")
    return (len(errors) == 0, ", ".join(errors))


def derive_password(pw: str, salt: bytes = None) -> (str, str):
    if salt is None:
        salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, 100_000)
    return base64.b64encode(salt).decode("ascii"), dk.hex()


def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_user(name: str, email: str, salt_b64: str, pw_hash_hex: str):
    users = load_users()
    if email in users:
        raise ValueError("Usuario con ese email ya existe")
    users[email] = {"name": name, "salt": salt_b64, "pw_hash": pw_hash_hex}
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2, ensure_ascii=False)


def build_gui():
    root = tk.Tk()
    root.title("Registro de Usuario")

    tk.Label(root, text="Nombre").grid(row=0, column=0, sticky="w", padx=6, pady=6)
    entry_name = tk.Entry(root, width=35)
    entry_name.grid(row=0, column=1, padx=6, pady=6)

    tk.Label(root, text="Email").grid(row=1, column=0, sticky="w", padx=6, pady=6)
    entry_email = tk.Entry(root, width=35)
    entry_email.grid(row=1, column=1, padx=6, pady=6)

    tk.Label(root, text="Contraseña").grid(row=2, column=0, sticky="w", padx=6, pady=6)
    entry_pw = tk.Entry(root, width=35, show="*")
    entry_pw.grid(row=2, column=1, padx=6, pady=6)

    show_var = tk.IntVar(value=0)

    def toggle_show():
        entry_pw.config(show="" if show_var.get() else "*")

    tk.Checkbutton(root, text="Mostrar contraseña", variable=show_var, command=toggle_show).grid(
        row=3, column=1, sticky="w", padx=6
    )

    lbl_strength = tk.Label(root, text="", fg="red")
    lbl_strength.grid(row=4, column=1, sticky="w", padx=6)

    def on_pw_change(event=None):
        pw = entry_pw.get()
        ok, msg = password_strength_info(pw)
        lbl_strength.config(text="OK" if ok else "Insegura: " + msg, fg="green" if ok else "red")

    entry_pw.bind("<KeyRelease>", on_pw_change)

    def on_submit():
        name = entry_name.get().strip()
        email = entry_email.get().strip()
        pw = entry_pw.get()

        if not name:
            messagebox.showerror("Error", "El nombre es obligatorio.")
            return
        if not is_valid_email(email):
            messagebox.showerror("Error", "Email no válido.")
            return
        ok, msg = password_strength_info(pw)
        if not ok:
            messagebox.showerror("Error", f"Contraseña insegura: {msg}")
            return

        try:
            salt_b64, pw_hash = derive_password(pw)
            save_user(name, email, salt_b64, pw_hash)
            messagebox.showinfo("Registro", "Usuario registrado correctamente.")
            entry_name.delete(0, tk.END)
            entry_email.delete(0, tk.END)
            entry_pw.delete(0, tk.END)
            lbl_strength.config(text="")
        except ValueError as e:
            messagebox.showerror("Error", str(e))
        except Exception:
            messagebox.showerror("Error", "No se pudo guardar el usuario.")

    btn_register = tk.Button(root, text="Registrar", command=on_submit, width=15)
    btn_register.grid(row=5, column=1, pady=10)

    root.resizable(False, False)
    root.mainloop()


if __name__ == "__main__":
    build_gui()