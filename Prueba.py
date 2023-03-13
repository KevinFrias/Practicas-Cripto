import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad

# Define the key and IV (must be 16 bytes)
key = b'mysecretkey12345'
iv =  b'myiv123456789012'

#iv = os.urandom(16)

# Encrypt the input data
def encrypt_file(input_file, output_file):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        while True:
            data = f_in.read(16)
            if not data:
                break
            f_out.write(cipher.encrypt(pad(data, 16)))


# Decrypt the contents of the input file and write the plaintext to the output file
def decrypt_file(input_file, output_file):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        while True:
            data = f_in.read(16)

            if not data:
                break

            # Decrypt the ciphertext and write it to the output file
            plaintext = unpad(cipher.decrypt(data), 16)
            f_out.write(plaintext)


print("File name : ")
nombre_archivo = input()

nuevo_nombre = nombre_archivo.split('.')
nuevo_nombre[0] = nuevo_nombre[0] + "-c."
nuevo_nombre = "".join(nuevo_nombre)


encrypt_file(nombre_archivo, nuevo_nombre)
decrypt_file(nuevo_nombre, "decrifrar.txt")
