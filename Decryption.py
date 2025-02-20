from PIL import Image
from cryptography.fernet import Fernet
import base64

def generate_key(password: str) -> bytes:
    """Generate a key from the password."""
    key = base64.urlsafe_b64encode(password.encode('utf-8').ljust(32)[:32])
    return key

def decrypt_message(encrypted_message: bytes, password: str) -> str:
    """Decrypt the message using the password."""
    key = generate_key(password)
    fernet = Fernet(key)
    decrypted_message = fernet.decrypt(encrypted_message).decode()
    return decrypted_message

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

# Example usage for decoding
if __name__ == "__main__":
    # Ask user if they want to decode the message
    decode_choice = input("Do you want to decode the message from the image? (yes/no): ")
    if decode_choice.lower() in ['yes', 'y']:
        password_for_decoding = input("Enter the decryption password: ")
        try:
            encrypted_message = decode_message_from_image('encoded_image.png')
            decoded_message = decrypt_message(encrypted_message, password_for_decoding)
            print("Decoded message:", decoded_message)  # Only display the decoded message
        except Exception as e:
            print("Failed to decode the message. Please check your password and try again.")
