import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox

import Crypto 
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

import sys
import atexit
import threading
import time
import hashlib
import ast
import cryptography
import rsa
import binascii

# Creamos la ventana de la aplicacion
window = tk.Tk()
window.title("Generacion y Verificacion")
window.geometry("400x450")
#window.resizable(False, False)  

def limpiar_pantalla() :
    # Limpiamos la pantalla
    for widgets in window.winfo_children():
        widgets.destroy()

def pedir_archivo(opcion, archivo_texto, archivo_llave, tipo_archivo):
    ruta_archivo = filedialog.askopenfilename()

    if tipo_archivo == 1 :
        pedir_informacion(opcion, ruta_archivo, archivo_llave)
    else :
        pedir_informacion(opcion, archivo_texto, ruta_archivo,)


def iniciar_proceso(opcion, archivo_texto, archivo_llave):

    if len(archivo_texto) == 0 :
        messagebox.askokcancel(message="No fue seleccionado algun archivo", title="Error")
        menu()
        return ''

    if len(archivo_llave) == 0 :
        messagebox.askokcancel(message="No fue seleccionada alguna llave", title="Error")
        menu()
        return ''

    # Declaramos una variable para poder almacenar toda la informacion contenida dentro del archivo
    contenido = ""

    with open(archivo_texto) as f:
        contenido = f.readlines()

    hash_opcional = contenido[-1]

    if opcion == 2 :
        contenido.pop()

    string_contenido = ''.join(contenido)
    hash_contenido = hashlib.sha1(string_contenido.encode())
    hash_contenido = hash_contenido.hexdigest()

    llave = ""

    if opcion == 1:
        with open (archivo_llave, 'rb') as f:
            llave = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        
        hash_contenido_RSA = hash_contenido.encode('utf-8')

        hash_contenido_RSA = llave.sign(
            hash_contenido_RSA,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )


        hash_contenido_RSA = hash_contenido_RSA.hex()

        output = open("salida.txt", "w")

        for i in contenido :
            output.write(i)

        output.write(hash_contenido_RSA)

        output.close()

        messagebox.showinfo("Proceso completado", "Mensaje generado")

        menu()
        return ''
        
    else :
        
        with open(archivo_llave, 'rb') as key_file:
            llave = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )

        hash_opcional = binascii.unhexlify(hash_opcional)
        hash_contenido = bytes(hash_contenido.encode('utf-8'))

        bandera = False

        try :
            mensaje = llave.verify(
                hash_opcional,
                hash_contenido,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                    ),
                hashes.SHA256()
            )
            messagebox.showinfo(message="Correcto :)", title="Good")
            menu()
            return ''
        except Exception :
            messagebox.showerror(message="Error :(", title="Error")
            menu()
            return ''


def pedir_informacion(opcion, archivo_texto, archivo_llave):

    # Limpiamos la pantalla de los demas widgets para poder mostrar correctamente esta pantalla
    limpiar_pantalla()

    # Creamos el boton para que sea seleccionado, sea el caso, la llave para la continuacion del programa
    archivo_texto_boton = tk.Button(window, width=35, height=3, text="Seleccionar archivo", bg='#cccccc', command=lambda:(pedir_archivo(opcion, archivo_texto, archivo_llave, 1)))
    archivo_texto_boton.pack(side=tk.TOP, pady=(50, 0))

    # En caso de que sea seleccionado el boton de la seleccion del archivo para la llave, mostramos el nombre del archivo
    nombre_archivo_texto = tk.Label(window, height = 3, text = archivo_texto.split('/')[-1], font='helvetica 14')
    nombre_archivo_texto.pack(side=tk.TOP, pady=(0, 10))


    # Creamos el boton para que sea seleccionado, sea el caso, la llave para la continuacion del programa
    llave_boton = tk.Button(window, width=35, height=3, text="Seleccionar llave", bg='#cccccc', command=lambda:(pedir_archivo(opcion, archivo_texto, archivo_llave, 2)))
    llave_boton.pack(side=tk.TOP, pady=(10, 0))

    # En caso de que sea seleccionado el boton de la seleccion del archivo para la llave, mostramos el nombre del archivo
    nombre_archivo_llave = tk.Label(window, height = 3, text = archivo_llave.split('/')[-1], font='helvetica 14')
    nombre_archivo_llave.pack(side=tk.TOP, pady=(0, 10))

    # Creamos el boton para dar comienzo al proceso del programa
    ok_boton = tk.Button(window, width=35, height=3, text="OK", bg='#cccccc', command=lambda:(iniciar_proceso(opcion, archivo_texto, archivo_llave)))
    ok_boton.pack(side=tk.BOTTOM, pady=(0, 10))
    return ''


def menu():
    limpiar_pantalla()

    # Create the second button and add it below the first button
    archivo_boton = tk.Button(window, width=35, height=3, text="Generar mensaje", command=lambda:(pedir_informacion(1, "", "")))
    archivo_boton.pack(side=tk.TOP, pady=(100,5))

    # Create the second button and add it below the first button
    archivo_boton = tk.Button(window, width=35, height=3, text="Verificar mensaje", command=lambda:(pedir_informacion(2, "", "")))
    archivo_boton.pack(side=tk.TOP, pady=(100,5))



def on_closing():
    sys.exit()
window.protocol("WM_DELETE_WINDOW", on_closing)

def exit_handler():
    for thread in threading.enumerate():
        if thread is not threading.main_thread():
            thread.join()
atexit.register(exit_handler)

menu()

# Iniciamos el programa
window.mainloop()
