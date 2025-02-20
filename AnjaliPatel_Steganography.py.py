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

def decrypt_message(encrypted_message: bytes, password: str) -> str:
    """Decrypt the message using the password."""
    key = generate_key(password)
    fernet = Fernet(key)
    decrypted_message = fernet.decrypt(encrypted_message).decode()
    return decrypted_message

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

def decode_message_from_image(image_path: str) -> bytes:
    """Decode the message from the image."""
    img = Image.open(image_path)
    img_data = img.getdata()

    # Extract the encrypted message from the image
    encrypted_message_bytes = bytearray()
    for pixel in img_data:
        encrypted_message_bytes.append(pixel[3])  # Assuming the message is stored in the alpha channel

    encrypted_message = bytes(encrypted_message_bytes)
    return encrypted_message

# Example usage
if __name__ == "__main__":
    # Get user input for message and password
    message = input("Enter the message you want to hide: ")
    password = input("Enter the encryption password: ")

    # Encode the message in the image
    encode_message_in_image('image.png', message, password)  # Ensure this is a PNG image

    # Ask user if they want to decode the message
    decode_choice = input("Do you want to decode the message from the image? (yes/no): ")
    if decode_choice.lower() in ['yes', 'y']:
        password_for_decoding = input("Enter the decryption password: ")
        try:
            encrypted_message = decode_message_from_image('encoded_image.png')
            # Removed the print statement for the encrypted message
            decoded_message = decrypt_message(encrypted_message, password_for_decoding)
            print("Decoded message:", decoded_message)  # Only display the decoded message
        except Exception as e:
            print("Failed to decode the message. Please check your password and try again.")
