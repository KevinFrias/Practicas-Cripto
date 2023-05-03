from Crypto.Cipher import AES
import base64

# Definir la clave de cifrado y el mensaje a cifrar
key = b'mi_clave_secreta_'
message = b'mi mensaje secreto'

# Rellenar el mensaje si no es un múltiplo de 16 bytes
# (esto es necesario para usar AES en modo ECB)
padding_length = 16 - (len(message) % 16)
message += bytes([padding_length]) * padding_length

# Crear el objeto de cifrado AES en modo ECB
cipher = AES.new(key, AES.MODE_ECB)

# Cifrar el mensaje
ciphertext = cipher.encrypt(message)

# Codificar el resultado en base64 para facilitar su lectura
encoded_ciphertext = base64.b64encode(ciphertext)
print("Mensaje cifrado:", encoded_ciphertext)

# Descifrar el mensaje
decrypted_message = cipher.decrypt(ciphertext)

# Eliminar el relleno agregado previamente
padding_length = decrypted_message[-1]
decrypted_message = decrypted_message[:-padding_length]

# Mostrar el mensaje descifrado
print("Mensaje descifrado:", decrypted_message)