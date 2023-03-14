from PIL import Image


def cifrar_imagen(nombre_imagen_entrada, nombre_imagen_salida) :
    # Open the BMP image file
    image = Image.open(nombre_imagen_entrada)

    # Get the width and height of the image
    width, height = image.size

    # Create a new image object with the same size and mode as the original image
    new_image = Image.new("RGB", (width, height))

    # Loop through each pixel in the image
    for y in range(height):
        for x in range(width):
            r,g,b = 0,0,0

            if image.mode == "RGB":
                r, g, b = image.getpixel((x, y))
            elif image.mode == "L":
                r = g = b = image.getpixel((x, y))

            # Modify the RGB values (e.g. invert the colors)
            r = 255 - r
            g = 255 - g
            b = 255 - b

            # Set the modified RGB values for the new pixel
            new_image.putpixel((x, y), (r, g, b))

    # Save the new image as a BMP file
    new_image.save(nombre_imagen_salida)


def decifrar_imagen(nombre_imagen_entrada, nombre_imagen_salida) :
    # Open the BMP image file
    image = Image.open(nombre_imagen_entrada)

    # Get the width and height of the image
    width, height = image.size

    # Create a new image object with the same size and mode as the original image
    new_image = Image.new("RGB", (width, height))

    # Loop through each pixel in the image
    for y in range(height):
        for x in range(width):
            r,g,b = 0,0,0

            if image.mode == "RGB":
                r, g, b = image.getpixel((x, y))
            elif image.mode == "L":
                r = g = b = image.getpixel((x, y))

            # Modify the RGB values (e.g. invert the colors)
            r  = 255 - r
            g  = 255 - g
            b  = 255 - b

            # Set the modified RGB values for the new pixel
            new_image.putpixel((x, y), (r, g, b))

    # Save the new image as a BMP file
    new_image.save(nombre_imagen_salida)