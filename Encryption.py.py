from PIL import Image
from cryptography.fernet import Fernet
import base64

def generate_key(password: str) -> bytes:
    """Generate a key from the password."""
    key = base64.urlsafe_b64encode(password.encode('utf-8').ljust(32)[:32])
    return key

def encrypt_message(message: str, password: str) -> bytes:
    """Encrypt the message using the password."""
    key = generate_key(password)
    fernet = Fernet(key)
    encrypted_message = fernet.encrypt(message.encode())
    return encrypted_message

def encode_message_in_image(image_path: str, message: str, password: str):
    """Encode the message into the image."""
    encrypted_message = encrypt_message(message, password)
    img = Image.open(image_path)

    # Convert image to RGBA if it's not already
    if img.mode != 'RGBA':
        img = img.convert('RGBA')

    img_data = img.getdata()

    # Convert the encrypted message to a list of pixel values
    encrypted_message_bytes = bytearray(encrypted_message)
    new_data = []
    for i, pixel in enumerate(img_data):
        if i < len(encrypted_message_bytes):
            # Modify the pixel to include the encrypted message
            new_pixel = (pixel[0], pixel[1], pixel[2], encrypted_message_bytes[i])
            new_data.append(new_pixel)
        else:
            new_data.append(pixel)

    # Create a new image with the modified data
    img.putdata(new_data)
    img.save('encoded_image.png')
    print("Message encoded in image and saved as 'encoded_image.png'.")

# Example usage for encoding
if __name__ == "__main__":
    # Get user input for message and password
    message = input("Enter the message you want to hide: ")
    password = input("Enter the encryption password: ")

    # Encode the message in the image
    encode_message_in_image('image.png', message, password)  # Ensure this is a PNG image
