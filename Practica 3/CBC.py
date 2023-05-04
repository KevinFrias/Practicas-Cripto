from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os


def cifrar(llave, v0, archivo_entrada, archivo_salida):

    cipher = AES.new(llave, AES.MODE_CBC, v0)

    with open(archivo_entrada, 'rb') as entrada, open(archivo_salida, 'wb') as salida:

        while True :
            bloque = entrada.read(16)

            if not bloque :
                break

            bloque_pad = pad(bloque, 16)
            salida.write(cipher.encrypt(bloque_pad))


def descifrar(llave, v0, archivo_entrada, archivo_salida):

    cipher = AES.new(llave, AES.MODE_CBC, v0)

    with open(archivo_entrada, 'rb') as entrada, open(archivo_salida, 'wb') as salida:

        while True :
            bloque = entrada.read(32)

            if not bloque :
                break
            
            if len(bloque) % 16 != 0 :
                bloque = pad(bloque, 16)

            
            bloque_unpad = unpad(cipher.decrypt(bloque), 16)

            salida.write(bloque_unpad)