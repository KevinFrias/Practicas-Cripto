from Crypto.Cipher import AES

def cifrar(llave, archivo_entrada, archivo_salida):
    # Open the input and output files
    with open(archivo_entrada, 'rb') as entrada, open(archivo_salida, 'wb') as salida:
        # Create the AES cipher with ECB mode
        cipher = AES.new(llave, AES.MODE_ECB)
        
        # Read and encrypt the file in chunks of 16 bytes (AES block size)
        while True:
            bloque = entrada.read(16)
            # Si es que ya acabamos de leer el archivo podemos acabar el ciclo
            if len(bloque) == 0:
                break

            # Si el bloque que leemos no es divisble entre 16 le agregamos un padding
            elif len(bloque) % 16 != 0:
                # En este caso le agregamos espacios
                bloque += b' ' * (16 - len(bloque) % 16)
            
            # Escribimos el blqque cifrado al archivo de salida
            salida.write(cipher.encrypt(bloque))


def descifrar(llave, archivo_entrada, archivo_salida):
    # Open the input and output files

    with open(archivo_entrada, 'rb') as entrada, open(archivo_salida, 'wb') as salida:
        # Create the AES cipher with ECB mode
        cipher = AES.new(llave, AES.MODE_ECB)
        
        # Read and decrypt the file in chunks of 16 bytes (AES block size)
        while True:
            bloque = entrada.read(16)

            if len(bloque) == 0:
                break
            
            bloque_descifrado = cipher.decrypt(bloque)
            salida.write(bloque_descifrado.strip())