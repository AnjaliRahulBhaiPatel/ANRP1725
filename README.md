Secure Data Hiding In Images Using Steganography
---------------------------------------------------------
SteganoCrypt lets you hide secret messages in images using a method called Least Significant Bit (LSB) encoding. It keeps your messages safe by using a passcode for both hiding and retrieving them.

Features
----------------------------------------------------------
* Message Encryption: The code allows you to encrypt a secret message using a password.

* Image Encoding: The encrypted message can be embedded into an image (PNG format) using the 
  Least Significant Bit (LSB) method.

* Image Decoding: You can extract the hidden message from the image if you provide the correct 
  password.

* User Input: The program prompts the user for a message and password, making it interactive.

* Error Handling: The code includes basic error handling for decryption failures.

Requirements
-------------------------------------------------------------
* Python: Make sure you have Python installed (preferably version 3.6 or higher).

* Pillow Library: This library is used for image processing. You can install it using:
  pip install Pillow

* Cryptography Library: This library is used for encrypting and decrypting messages. You can 
  install it using:
   pip install cryptography

Installation
---------------------------------------------------------------
1. Install Python: Download and install Python from the official website: python.org

2. Install Required Libraries: Open your command line or terminal and run the following 
   commands:
   pip install Pillow
   pip install cryptography

3. Save the Code: Copy the provided code into a Python file, for example, steganography.py.

4. Prepare an Image: Ensure you have a PNG image (e.g., image.png) in the same directory as 
   your Python file.

5. Run the Program: Execute the script using the command:
   python steganography.py

6. Follow Prompts: Enter the message you want to hide and the password when prompted. After 
   encoding, you can choose to decode the message by providing the correct password.
