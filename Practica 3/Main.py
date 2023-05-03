import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox

import sys
import atexit
import threading
import time

import ECB


# Creamos la ventana de la aplicacion
window = tk.Tk()
window.title("Cifrado y Descifrado")
window.geometry("800x600")
#window.resizable(False, False)  

def limpiar_pantalla() :
    # Limpiamos la pantalla
    for widgets in window.winfo_children():
        widgets.destroy()

def seleccionar_cifrado_descifrado(action, option, ruta, llave, ruta_archivo) : 

    if option == "ECB":


    if option == "CBC":


    if option == "CBF":


    if option == "OBF":


def action_handler(action, option, llave, vector0, ruta_archivo):
    nombre_archivo = ruta_archivo.split('/')
    nombre_archivo = nombre_archivo[len(nombre_archivo) - 1]

    nueva_ruta = ruta_archivo.split(nombre_archivo)

    nombre_archivo = nombre_archivo.split('.')

    nuevo_archivo = nombre_archivo[0] + "_" + action + option + "." + nombre_archivo[1]
    nueva_ruta[0]+=nuevo_archivo

    print(nueva_ruta[0])





def pedir_datos(llave, vector0, ruta_archivo) :

    limpiar_pantalla()

    # --------------------------------------------------------------------------
    cypher_action = tk.StringVar(value="e")

    # Create a frame to hold the radio buttons
    frame_cypher_action = tk.Frame(window, width=300)

    # Create the radio buttons inside the frame
    option1_a = tk.Radiobutton(frame_cypher_action, width=25, height=3, text="Cifrado", font='helvetica 14', variable=cypher_action, value="e")
    option2_a = tk.Radiobutton(frame_cypher_action, width=25, height=3, text="Descifrado", font='helvetica 14', variable=cypher_action, value="d")

    # Pack the radio buttons into the frame
    option1_a.pack()
    option2_a.pack()

    # Pack the frame into the window
    frame_cypher_action.pack(side=tk.LEFT, padx=(50,0), pady=(50,300))
    # --------------------------------------------------------------------------





    # --------------------------------------------------------------------------

    # Create a variable to hold the selected option
    cypher_option = tk.StringVar(value="ECB")

    # Create a frame to hold the radio buttons
    frame_cypher_option = tk.Frame(window, width=300)

    # Create the radio buttons inside the frame
    option1 = tk.Radiobutton(frame_cypher_option, width=25, height=3, text="ECB", font='helvetica 14', variable=cypher_option, value="ECB")
    option2 = tk.Radiobutton(frame_cypher_option, width=25, height=3, text="CBC", font='helvetica 14', variable=cypher_option, value="CBC")
    option3 = tk.Radiobutton(frame_cypher_option, width=25, height=3, text="CFB", font='helvetica 14', variable=cypher_option, value="CFB")
    option4 = tk.Radiobutton(frame_cypher_option, width=25, height=3, text="OFB", font='helvetica 14', variable=cypher_option, value="OFB")

    # Pack the radio buttons into the frame
    option1.pack()
    option2.pack()
    option3.pack()
    option4.pack()

    # Pack the frame into the window
    frame_cypher_option.pack(side=tk.RIGHT, padx=(0,80), pady=(50,300))
    # --------------------------------------------------------------------------


    # Create the second button and add it below the first button
    ok_boton = tk.Button(window, width=35, height=3, text="OK", command=lambda:action_handler(cypher_action.get(), cypher_option.get(), llave, vector0, ruta_archivo))
    ok_boton.pack(side=tk.BOTTOM, pady=15)
    
    nombre_archivo = ruta_archivo.split('/')
    nombre_archivo = nombre_archivo[len(nombre_archivo) - 1]

    # Etiqueta para mostrar el nombre del archivo seleccionado
    nombre_archivo_label = tk.Label(window, height = 3, text = nombre_archivo, font='helvetica 14')
    nombre_archivo_label.pack(side=tk.TOP)

def comprobacion_input(llave, vector0, ruta_archivo):
    delta = 0

    if len(ruta_archivo) == 0 :
        menu("", "", "", 0)
        return ''

    if len(llave.encode("utf-8")) != 16:
        delta += 1

    if len(vector0.encode("utf-8")) != 16:
        delta += 2

    if delta == 0 :
        pedir_datos(llave, vector0, ruta_archivo)
    else :
        llave = llave.strip()
        vector0 = vector0.strip()

        menu(llave, vector0, ruta_archivo, delta)

    return 

def pedir_archivo(llave, v0):
    # Cremaos la ventana para poder pedir el archivo
    ruta_archivo= filedialog.askopenfilename()

    if len(ruta_archivo) == 0 :
        menu("", "", "", 0)
        return ''

    llave = llave.strip()
    v0 = v0.strip()

    menu(llave, v0, ruta_archivo, 0)

def menu(llave, v0, ruta_archivo, delta):
    limpiar_pantalla()

    nombre_archivo = ruta_archivo.split('/')
    nombre_archivo = nombre_archivo[len(nombre_archivo) - 1]

    # Create the second button and add it below the first button
    archivo_boton = tk.Button(window, width=35, height=3, text="Seleccionar Archivo", command=lambda:pedir_archivo(llave_input.get("0.0",'end-0c'), vector0_input.get("0.0",'end-0c')))
    archivo_boton.pack(side=tk.TOP, pady=(20,0))

    # Etiqueta para mostrar el nombre del archivo seleccionado
    nombre_archivo_label = tk.Label(window, height = 3, text = nombre_archivo, font='helvetica 14')
    nombre_archivo_label.pack(side=tk.TOP, pady=(0,10))


    # Etiqueta para mostrar el nombre del archivo seleccionado
    llave_label = tk.Label(window, height = 3, text = "Llave : ", font='helvetica 14')
    llave_label.pack(side=tk.TOP)

    #Pedimos la lista de adyacencia
    llave_input = tk.Text(window, height = 1, width = 25,bg = "white", font=('Georgia 18') )
    llave_input.insert("0.0", llave)
    llave_input.pack(side= tk.TOP, pady=(0, 20))


    # Etiqueta para mostrar el nombre del archivo seleccionado
    vector0_label = tk.Label(window, height = 3, text = "Vector de Inicialización (C0) : ", font='helvetica 14')
    vector0_label.pack(side=tk.TOP)

    #Pedimos la lista de adyacencia
    vector0_input = tk.Text(window, height = 1, width = 25, bg = "white", font=('Georgia 18') )
    vector0_input.insert("0.0", v0)
    vector0_input.pack(side= tk.TOP, pady=(0, 20))


    if delta == 1 :
        llave_label.configure( text = "Llave : *La llave debe ser de 16 bytes", fg="red")
    elif delta == 2:
        vector0_label.configure( text = "Vector de Inicialización (C0) :  * Debe ser de 16 bytes", fg="red")
    elif delta == 3:
        llave_label.configure( text = "Llave : *La llave debe ser de 16 bytes", fg="red")
        vector0_label.configure( text = "Vector de Inicialización (C0) :  * Debe ser de 16 bytes", fg="red")


    # Create the second button and add it below the first button
    ok_boton = tk.Button(window, width=35, height=3, text="OK", command=lambda:comprobacion_input(llave_input.get("0.0",'end-0c'), vector0_input.get("0.0",'end-0c'), ruta_archivo))
    ok_boton.pack(side=tk.BOTTOM, pady=20)
    



def on_closing():
    sys.exit()

window.protocol("WM_DELETE_WINDOW", on_closing)

def exit_handler():
    for thread in threading.enumerate():
        if thread is not threading.main_thread():
            thread.join()

atexit.register(exit_handler)


menu("", "", "", 0)

# Iniciamos el programa
window.mainloop()