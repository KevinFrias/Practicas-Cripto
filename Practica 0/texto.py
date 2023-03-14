import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad

# Define the key and IV (must be 16 bytes)
key = b'mysecretkey12345'
iv =  b'myiv123456789012'

#iv = os.urandom(16)

# Cifrar el archivo de entrada
def cifrar_archivo(input_file, output_file):
    cipher = AES.new(key, AES.MODE_CBC, iv)
        # Abrimos el archivo y creamos el archivo de salida
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        while True:
            # Leemos los datos de entrada
            data = f_in.read(16)
            # En caso de ya no tener informacion del arhivo de entrada, acabos con el descifrado
            if not data:
                break
            
            # Ciframos el texto y lo ponemos en el archivo de salida
            f_out.write(cipher.encrypt(pad(data, 16)))


# Decifrar el contenido del archivo de entrada y escribirlo en el segundo argumento de la funcion
def decifrar_archivo(input_file, output_file):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Abrimos el archivo y creamos el archivo de salida
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        while True:
            # Leemos los datos de entrada
            data = f_in.read(16)

            # En caso de ya no tener informacion del arhivo de entrada, acabos con el descifrado
            if not data:
                break

            # Decifrar el texto cifrado y escribirlo en el archivo de salida
            plaintext = unpad(cipher.decrypt(data), 16)
            f_out.write(plaintext)
