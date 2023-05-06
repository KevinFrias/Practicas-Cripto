from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from PIL import Image

def cifrar(llave, v0, archivo_entrada, archivo_salida):
    cipher = AES.new(llave, AES.MODE_CFB, v0)
    imagen = Image.open(archivo_entrada)
    imagen_bytes = imagen.tobytes()
    imagen_cifrado = cipher.encrypt(pad(imagen_bytes, AES.block_size))
    imagen_cifrado = Image.frombytes(imagen.mode, imagen.size, imagen_cifrado)
    imagen_cifrado.save(archivo_salida)


def descifrar(llave, v0, archivo_entrada, archivo_salida):    
    cipher = AES.new(llave, AES.MODE_CFB, v0)
    imagen_cifrado = Image.open(archivo_entrada)
    imagen_bytes = imagen_cifrado.tobytes()
    imagen_bytes = pad(imagen_bytes, AES.block_size)

    imagen_bytes = cipher.decrypt(imagen_bytes)
    
    imagen_descifrado = Image.frombytes(imagen_cifrado.mode, imagen_cifrado.size, imagen_bytes)

    imagen_descifrado.save(archivo_salida)
