import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox

import sys
import atexit
import threading
import time

import texto

# Creamos la ventana de la aplicacion
window = tk.Tk()
window.title("Cifrado y Descifrado")
window.geometry("800x600")
#window.resizable(False, False)  

ruta_archivo = ""


def limpiar_pantalla() :
    # Limpiamos la pantalla
    for widgets in window.winfo_children():
        widgets.destroy()


def seleccionar_cifrado_descifrado(opcion, ruta) : 

    extension = ruta.split('.')
    extension = extension[len(extension) - 1]

    nombre_archivo = ruta.split('/')
    nombre_archivo_entrada = nombre_archivo[len(nombre_archivo) - 1]
    nombre_archivo = nombre_archivo_entrada.split('.')


    if (extension == "txt") :
        if (opcion == 1) :
            texto.encrypt_file(nombre_archivo_entrada, nombre_archivo[0] + "-C." + nombre_archivo[1])
            messagebox.showinfo("Proceso Completado","Cifrado Realizado")
            menu()
        else :
            texto.decrypt_file(nombre_archivo_entrada, nombre_archivo[0] + "-D." + nombre_archivo[1])
            messagebox.showinfo("Proceso Completado","Decifrado Realizado")
            menu()

    elif (extension == "bmp") :
        print("asndasjkdnasjd")

    else :
        print("22")
        window.destroy()
        return ''


def pedir_archivo() :
    # Show the file dialog and get the selected file path
    global ruta_archivo 
    ruta_archivo= filedialog.askopenfilename()

    nombre_archivo = ruta_archivo.split('/')
    nombre_archivo = nombre_archivo[len(nombre_archivo) - 1]


    # Etiqueta para mostrar el nombre del archivo seleccionado
    nombre_archivo_label = tk.Label(window, height = 1, text = nombre_archivo, font='helvetica 14')
    nombre_archivo_label.pack(side=tk.TOP)

    # Create the first button and add it to the top of the frame
    cifrado_boton = tk.Button(window, width=35, height=3, text="Cifrar", command=lambda:seleccionar_cifrado_descifrado(1, ruta_archivo))
    cifrado_boton.pack(side="left", expand=True)

    # Create the second button and add it below the first button
    descifrado_boton = tk.Button(window, width=35, height=3, text="Descifrar", command=lambda:seleccionar_cifrado_descifrado(2, ruta_archivo))
    descifrado_boton.pack(side="left", expand=True)


def menu():
    limpiar_pantalla()

    # Create the second button and add it below the first button
    archivo_boton = tk.Button(window, width=35, height=3, text="Seleccionar Archivo", command=pedir_archivo)
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