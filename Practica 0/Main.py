import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox

import sys
import atexit
import threading
import time

import texto
import imagen


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

    if len(ruta) == 0 :
        menu()
        return''

    # Primero obtenemos la extension del archivo con el cual vamos a trabajar
    extension = ruta.split('.')
    extension = extension[len(extension) - 1]


    # Luego, como queremos obtener el nombre del archivo, separamos la ruta 
    ruta_separada = ruta.split('/')

    # Obtenemos el nombre del archivo
    archivo_entrada = ruta_separada[len(ruta_separada) - 1]
    nombre_temporal = archivo_entrada.split('.')


    # Como hay que indicar si el archivo es cifrado o descifrado le agregamos la letra correspondiente
    temporal = ""

    if (opcion == 1) :
        temporal = "-C."
    else :
        temporal = "-D."


    # Creamos y guardamos el nombre de salida y hacemos lo mismo para el de entrada
    archivo_salida = nombre_temporal[0] + temporal + nombre_temporal[1]

    archivo_entrada =  "/".join(ruta_separada[:-1]) + "/" + archivo_entrada
    archivo_salida =  "/".join(ruta_separada[:-1]) + "/" + archivo_salida


    if (extension == "txt") :
        if (opcion == 1) :
            texto.cifrar_archivo(archivo_entrada, archivo_salida)
            messagebox.showinfo("Proceso Completado","Cifrado Realizado")
            menu()
        else :
            texto.decifrar_archivo(archivo_entrada, archivo_salida)
            messagebox.showinfo("Proceso Completado","Decifrado Realizado")
            menu()

    elif (extension == "bmp") :
        if (opcion == 1) :
            imagen.cifrar_imagen(archivo_entrada, archivo_salida)
            messagebox.showinfo("Proceso Completado","Cifrado Realizado")
            menu()
        else :
            imagen.decifrar_imagen(archivo_entrada, archivo_salida)
            messagebox.showinfo("Proceso Completado","Decifrado Realizado")
            menu()

    else :
        messagebox.showerror("Error archivo","Formato de archivo no soportado")
        menu()
        return ''




def pedir_archivo() :
    # Show the file dialog and get the selected file path
    global ruta_archivo 
    ruta_archivo= filedialog.askopenfilename()

    if len(ruta_archivo) == 0 :
        menu()
        return ''

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