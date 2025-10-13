from flask import Flask, render_template, request, redirect, url_for, session
import json
import os
import re

app = Flask(__name__)
app.secret_key = "clave_secreta"  # Necesario para manejar sesiones

USERS_FILE = "users.json"

# Cargar usuarios desde archivo
def cargar_usuarios():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        return json.load(f)

# Guardar usuarios en archivo
def guardar_usuarios(usuarios):
    with open(USERS_FILE, "w") as f:
        json.dump(usuarios, f)

def validar_password(password):
    errores = []

    if len(password) < 8:
        errores.append("Debe tener al menos 8 caracteres")
    if not re.search(r"[A-Z]", password):
        errores.append("Debe tener al menos una letra mayúscula")
    if not re.search(r"[a-z]", password):
        errores.append("Debe tener al menos una letra minúscula")
    if not re.search(r"\d", password):
        errores.append("Debe tener al menos un número")
    if not re.search(r"[\/\?\_\-\#\$\@\%\&\^\*\!\=\¿\+\¡\(\)]", password):
        errores.append("Debe tener al menos un carácter especial /?_-#$@%&^*!=¿+¡()")

    return errores

@app.route("/")
def index():
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    errores = []
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        confirm = request.form["confirm_password"]

        if password != confirm:
            errores.append("Las contraseñas no coinciden")

        # Validar complejidad
        errores += validar_password(password)

        usuarios = cargar_usuarios()
        if username in usuarios:
            errores.append("El usuario ya existe")

        # Si hay errores, volver a mostrar el formulario con mensajes
        if errores:
            # Pasamos también lo que el usuario escribió
            return render_template(
                "register.html",
                errores=errores,
                username=username,
                email=email,
                password="",  
                confirm_password=""
            )

        # Guardar usuario
        usuarios[username] = {"email": email, "password": password}
        guardar_usuarios(usuarios)
        return redirect(url_for("login"))

    return render_template("register.html", errores=errores)


@app.route("/login", methods=["GET", "POST"])
def login():
    errores = []
    username = ""
    password = ""
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        usuarios = cargar_usuarios()
        if username not in usuarios or usuarios[username]["password"] != password:
            errores.append("Usuario o contraseña incorrectos")
            # Volvemos a renderizar con los valores ingresados
            return render_template("login.html", errores=errores, username=username, password="")

        # Si es correcto, guardamos en sesión
        session["usuario"] = username
        return redirect(url_for("productos"))

    return render_template("login.html", errores=errores, username=username, password=password)


@app.route("/productos")
def productos():
    if "usuario" not in session:
        return redirect(url_for("login"))
    return render_template("productos.html", usuario=session["usuario"])

@app.route("/logout")
def logout():
    session.pop("usuario", None)
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)
