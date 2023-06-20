import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox

import Crypto 
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

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
import base64

# Creamos la ventana de la aplicacion
window = tk.Tk()
window.title("Generacion y Verificacion")
window.geometry("400x550")
#window.resizable(False, False)  


def iniciar_proceso(opcion, archivo_texto, archivo_llave, archivo_llave_B):

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

    hash_opcional = ''

    string_contenido = ''.join(contenido)

    if opcion == 2 :
        hash_opcional = string_contenido[-344:]
        string_contenido = string_contenido[:-344]

    hash_contenido = hashlib.sha1(string_contenido.encode())
    hash_contenido = hash_contenido.hexdigest()

    llave = ""

    # 1 -> Cifrar

    if opcion == 1:
        # Abrimos el archivo de la llave
        with open (archivo_llave, 'rb') as f:
            llave = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )

        firma_digital = ''

        firma_digital = llave.sign(
            hash_contenido.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        #Asignamos el valor del la firma digita
        firma_digital = firma_digital[:32]

        # Abrimos el archivo de salida
        output = open("salida.txt", "w")

        #######################################################################
        # Definimos el valor del vector de inicializacion
        iv = firma_digital[:16]

        # Creamos el objeto para cifrar usando AES en modo CBC ocupando la mismo iv y llave 
        cipher = AES.new(firma_digital, AES.MODE_CBC, iv)

        # Ciframos todo el contenido del archivo
        for i in contenido :
            string_contenido_temporal = i.encode('utf-8')
            mensaje_cifrado = cipher.encrypt(pad(string_contenido_temporal, AES.block_size))
            mensaje_cifrado_base64 = base64.b64encode(mensaje_cifrado).decode('utf-8')

            output.write(mensaje_cifrado_base64)
            #print(mensaje_cifrado_base64)

        #######################################################################

        # Creamos el archivo de la llave publica B
        llave_B = ''

        # Abrimos el archivo de la llave publica de B
        with open(archivo_llave_B, "rb") as f:
            llave_B = RSA.import_key(f.read())

        # Ciframos el mensaje
        cipher_rsa = PKCS1_OAEP.new(llave_B)
        firma_digital_rsa = cipher_rsa.encrypt(firma_digital)

        # Lo pasamos a base 64
        firma_digital_base64 = base64.b64encode(firma_digital_rsa).decode('utf-8')

        # Lo escribrimos dentro del archivo
        output.write(firma_digital_base64)

        # Cerramos el archivo
        output.close()

        # Mostramos en pantalla el mensaje de proceso completo junto y regresamos al menu principal
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



def pedir_archivo(opcion, archivo_texto, archivo_llave, archivo_llave2, tipo_archivo):
    ruta_archivo = filedialog.askopenfilename()

    if tipo_archivo == 1 :
        pedir_informacion(opcion, ruta_archivo, archivo_llave, archivo_llave2)
    elif tipo_archivo == 2 :
        pedir_informacion(opcion, archivo_texto, ruta_archivo, archivo_llave2)
    else :
        pedir_informacion(opcion, archivo_texto, archivo_llave, ruta_archivo)

def pedir_informacion(opcion, archivo_texto, archivo_llave, archivo_llave2):

    # Limpiamos la pantalla de los demas widgets para poder mostrar correctamente esta pantalla
    limpiar_pantalla()

    # Creamos el boton para que sea seleccionado, sea el caso, la llave para la continuacion del programa
    archivo_texto_boton = tk.Button(window, width=35, height=3, text="Seleccionar archivo", bg='#cccccc', command=lambda:(pedir_archivo(opcion, archivo_texto, archivo_llave, archivo_llave2, 1)))
    archivo_texto_boton.pack(side=tk.TOP, pady=(50, 0))

    # En caso de que sea seleccionado el boton de la seleccion del archivo para la llave, mostramos el nombre del archivo
    nombre_archivo_texto = tk.Label(window, height = 3, text = archivo_texto.split('/')[-1], font='helvetica 14')
    nombre_archivo_texto.pack(side=tk.TOP, pady=(0, 10))

    # Creamos el boton para que sea seleccionado, sea el caso, la llave para la continuacion del programa
    llave_boton = tk.Button(window, width=35, height=3, text="Seleccionar llave " + "privada" if opcion == 1 else "publica", bg='#cccccc', command=lambda:(pedir_archivo(opcion, archivo_texto, archivo_llave, archivo_llave2, 2)))
    llave_boton.pack(side=tk.TOP, pady=(10, 0))

    # En caso de que sea seleccionado el boton de la seleccion del archivo para la llave, mostramos el nombre del archivo
    nombre_archivo_llave = tk.Label(window, height = 3, text = archivo_llave.split('/')[-1], font='helvetica 14')
    nombre_archivo_llave.pack(side=tk.TOP, pady=(0, 10))
    
    # Creamos el boton para que sea seleccionado, sea el caso, la llave para la continuacion del programa
    llave_boton2 = tk.Button(window, width=35, height=3, text="Seleccionar llave "  + "publica" if opcion == 1 else "privada" , bg='#cccccc', command=lambda:(pedir_archivo(opcion, archivo_texto, archivo_llave, archivo_llave2, 3)))
    llave_boton2.pack(side=tk.TOP, pady=(10, 0))

    # En caso de que sea seleccionado el boton de la seleccion del archivo para la llave, mostramos el nombre del archivo
    nombre_archivo_llave2 = tk.Label(window, height = 3, text = archivo_llave2.split('/')[-1], font='helvetica 14')
    nombre_archivo_llave2.pack(side=tk.TOP, pady=(0, 10))
    

    # Creamos el boton para dar comienzo al proceso del programa
    ok_boton = tk.Button(window, width=35, height=3, text="OK", bg='#cccccc', command=lambda:(iniciar_proceso(opcion, archivo_texto, archivo_llave, archivo_llave)))
    ok_boton.pack(side=tk.BOTTOM, pady=(0, 10))
    return ''



def limpiar_pantalla() :
    # Limpiamos la pantalla
    for widgets in window.winfo_children():
        widgets.destroy()

def menu():
    limpiar_pantalla()

    # Create the second button and add it below the first button
    archivo_boton = tk.Button(window, width=35, height=3, text="Generar mensaje", command=lambda:(pedir_informacion(1, "", "", "")))
    archivo_boton.pack(side=tk.TOP, pady=(100,5))

    # Create the second button and add it below the first button
    archivo_boton = tk.Button(window, width=35, height=3, text="Verificar mensaje", command=lambda:(pedir_informacion(2, "", "", "")))
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