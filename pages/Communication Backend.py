import streamlit as st
import time
import hashlib
import rsa
from ecdsa import SigningKey, VerifyingKey, SECP256k1

# Define the substitution cipher
LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ'
LETTERS = LETTERS.lower()

def encrypt(message, key):
    encrypted = ''
    for chars in message:
        if chars in LETTERS:
            num = LETTERS.find(chars)
            num += key
            encrypted +=  LETTERS[num]

    return encrypted

def decrypt(message, key):
    decrypted = ''
    for chars in message:
        if chars in LETTERS:
            num = LETTERS.find(chars)
            num -= key
            decrypted +=  LETTERS[num]

    return decrypted

# Define the Streamlit app
def app():
    st.set_page_config(
        page_title="Communication Backend"
    )
    st.title('Communication System')

    # Get user input
    message1 = st.text_input('Enter your message for encryption:')
    key = st.slider('Enter your key [1 - 26]:', 1, 26)
    choice = st.selectbox('Encrypt or Decrypt?', ('Encrypt', 'Decrypt'))
    result = encrypt(message1, key)
    # Perform encryption or decryption based on user choice
    # if choice == 'Encrypt':
    #     result = encrypt(message, key)
    # else:
    #     result = decrypt(message, key)
    time.sleep(6)

    st.write('Result:', result)
    
    time.sleep(9)
    st.write('Starting blockchain encryption layer...')
    if result:
        time.sleep(3)
        a = "b843dd2f3cfa492d4fb4260a4c28968d7615492f9906b0ad6e2d7bbc5c69d7dc" 
        message = result
        c = "6156c9f7df237e11aab86dcd1e605fb69150c724a7e6da452939dd964d0d2973"
        blockres = a+message+c
        if blockres:

            st.write('Blockchain:', blockres)

            time.sleep(8)

            st.write('Starting double encryption layer...')
        
            dub =  result.encode('utf-8')
            (publicKey, privateKey) = rsa.newkeys(256)
            encrypted_message = rsa.encrypt(dub, publicKey)
            st.write(publicKey)
            st.write(privateKey)
            time.sleep(8)
            st.write('Encrypted Message: ' + str(encrypted_message))
            time.sleep(8)
            st.write('Decrypting message...')
            time.sleep(3)
            decrypted_message = rsa.decrypt(encrypted_message, privateKey)
            st.write('Decrypted Message: ' + decrypted_message.decode('utf-8'))
            time.sleep(3)
            choice = st.selectbox('Decrypt original message?', ('Decrypt', 'Encrypt'))

            # Perform encryption or decryption based on user choice
            if choice == 'Decrypt':
                result = decrypt(decrypted_message.decode('utf-8'), key)
                
            else:
                result = encrypt(message, key)
            time.sleep(4)
            st.write('Original message decryption...')
            # Display the result to the user
            st.write('Original message:', result)

            # Generate private and public key
            privateKey = SigningKey.generate(curve=SECP256k1)
            publicKey = privateKey.verifying_key
            # st.write('Private Key: ' + str(privateKey.to_string()))
            # st.write('Public Key: ' + str(publicKey.to_string()))
            # st.write('\n')  

            message2 = message1
            if message2:
                def sha256_hash(message2):
                    return hashlib.sha256(message2.encode()).hexdigest()
                
                hash_message2 = sha256_hash(message2)
                # st.write('Original message: ' + decrypt(message2, keys))
                # st.write('SHA256 Hash Message: ' + hash_message2)
                # st.write('\n')

            # Digital Signature of Hash Message
            digital_signature = privateKey.sign(hash_message2.encode())
            st.write('Digital Signature: ' + str(digital_signature))
            st.write('\n')

            # Verify digital signature
            verified = publicKey.verify(digital_signature, hash_message2.encode())

            if verified:
                st.write('Message origin verified by digital signature')
            else:
                st.write('Message not from public/private key pair')

# Run the Streamlit app
if __name__ == '__main__':
    app()

