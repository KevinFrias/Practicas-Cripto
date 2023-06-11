from tkinter import *
from tkinter import filedialog

#----root declaration----
root=Tk()
root.title("Práctica 1")
root.geometry("750x350")
root.resizable(0,0)

#----Frame layout declarations-----
affinFrame = Frame(root, width="730", height="330")
affinFrame.place(x=10,y=10)
affinFrame.config(bg="#5FFFF4", bd=10, relief="groove")

namesFrame = Frame(root, width="230", height="80")
namesFrame.place(x=499,y=19)
namesFrame.config(bg="#0083FF", bd=3, relief="ridge")

#----variables declaration----

n = StringVar()
alfa = StringVar()
beta = StringVar()
error = StringVar()

cipherFunc = StringVar()
cipherFunc.set("Funcion Cifrado")

decipherFuncPrev = StringVar()
decipherFuncPrev.set("Funcion Decifrado previa")

decipherFuncFinal = StringVar()
decipherFuncFinal.set("Funcion Decifrado final")

#-----Actions-----

def GenerateFunctions():
    #Convertir de String a int
    if(beta.get()==""):
        error.set("Ingrese un valor para β.")
        betaValue = 0
        return 0
    else:
        betaValue = int(beta.get())
    if(alfa.get()==""):
        error.set("Ingrese un valor para α.")
        alfaValue = 0
        return 0
    else:
        alfaValue = int(alfa.get())
    if(n.get()==""):
        error.set("Ingrese un valor para n.")
        nValue = 0
        return 0
    else:
        nValue = int(n.get())

    #Verificar si b está en el rango de 0 a n
    if(not(betaValue>0 and betaValue<=nValue)):
        betaValue = encontrarEquivalencia(betaValue, nValue)
        beta.set(str(betaValue))
        error.set("β debe comprender en un rango de 0 a n. Su equivalente sería: "+beta.get()+".")
        return 0
    
    error.set("")
    #-Para función de cifrado:
    #--Verificar si es coprimo
    if(euclides(alfaValue,nValue) == 1):
        cipherFunc.set("C = "+alfa.get()+"p + "+beta.get()+" mod"+n.get())
    else:
        error.set("α no es coprimo con n, prueba con otro valor de α.")

def encontrarEquivalencia(b,n):
    while(b>n):
        b=b-n
    return b

def euclides(a,b):
    if b == 0: return a
    return euclides(b, a%b)

#-----affinFrame components----
titleAffin = Label(affinFrame, text="Cifrador Affin", fg="#3F938D",bg="#5FFFF4", font=("Arial", 16))
titleAffin.place(x=300,y=8)

#Entry Elements
nLabel = Label(affinFrame, text="n: ", fg="#3F938D",bg="#5FFFF4", font=("Arial", 13))
nLabel.place(x=8,y=55)

nEntry = Entry(affinFrame,textvariable=n, fg="#5FFFF4",bg="#00AEA2", font=("Arial", 12), width="7")
nEntry.place(x=32,y=56)

alfaLabel = Label(affinFrame, text="α: ", fg="#3F938D",bg="#5FFFF4", font=("Arial", 13))
alfaLabel.place(x=104,y=55)

alfaEntry = Entry(affinFrame,textvariable=alfa, fg="#5FFFF4",bg="#00AEA2", font=("Arial", 12), width="7")
alfaEntry.place(x=128,y=56)

betaLabel = Label(affinFrame, text="β: ", fg="#3F938D",bg="#5FFFF4", font=("Arial", 13))
betaLabel.place(x=200,y=55)

betaEntry = Entry(affinFrame,textvariable=beta, fg="#5FFFF4",bg="#00AEA2", font=("Arial", 12), width="7")
betaEntry.place(x=224,y=56)

affinButton = Button(affinFrame, text="Obtener Funciones", fg="#1F847D",bg="#57E0D6", font=("Arial", 10), command=GenerateFunctions)
affinButton.place(x=320,y=53)

#Error Message
messageErrorEntry = Label(affinFrame,textvariable=error, fg="#3F938D",bg="#5FFFF4", font=("Arial", 9))
messageErrorEntry.place(x=180,y=96)

#Output Elements
cipherFuncLabel = Label(affinFrame, text="Función de cifrado: ", fg="#3F938D",bg="#5FFFF4", font=("Arial", 13))
cipherFuncLabel.place(x=25, y=150)

cipherFuncEntry = Label(affinFrame, textvariable=cipherFunc, fg="#3F938D",bg="#5FFFF4", font=("Arial", 12))
cipherFuncEntry.place(x=29, y=180)

decipherFuncLabel = Label(affinFrame, text="Función de decifrado: ", fg="#3F938D",bg="#5FFFF4", font=("Arial", 13))
decipherFuncLabel.place(x=370, y=140)

decipherFuncPrevEntry = Label(affinFrame, textvariable=decipherFuncPrev, fg="#3F938D",bg="#5FFFF4", font=("Arial", 12))
decipherFuncPrevEntry.place(x=374, y=170)

decipherFuncFinalEntry = Label(affinFrame, textvariable=decipherFuncFinal, fg="#3F938D",bg="#5FFFF4", font=("Arial", 12))
decipherFuncFinalEntry.place(x=374, y=195)


#-----namesFrame components----
namesTitle = Label(namesFrame,text="Nombres de los integrantes", fg="#E5F2FF",bg="#0080FF", font=("Arial", 12))
namesTitle.place(x=20,y=2)

namesTitle = Label(namesFrame,text="Campos Ocampo Hugo Johan", fg="#E5F2FF",bg="#0080FF", font=("Arial", 9))
namesTitle.place(x=7,y=25)

namesTitle = Label(namesFrame,text="Frías Estrada Kevin", fg="#E5F2FF",bg="#0080FF", font=("Arial", 9))
namesTitle.place(x=7,y=45)

root.mainloop()