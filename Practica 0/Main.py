import tkinter as tk

import sys
import atexit
import threading
import time

def abrir_archivo(nnombre):
    sys.stdin = open(nombre + ".txt", "r")

def guardar_archivo(nombre):
    sys.stdout = open(nombre + "-c.txt", "w")


# Creamos la ventana de la aplicacion
window = tk.Tk()
window.title("Visualización")
window.geometry("800x600")
#window.resizable(False, False)  



def on_closing():
    sys.exit()
window.protocol("WM_DELETE_WINDOW", on_closing)

def exit_handler():
    for thread in threading.enumerate():
        if thread is not threading.main_thread():
            thread.join()
atexit.register(exit_handler)


# Iniciamos el programa
window.mainloop()