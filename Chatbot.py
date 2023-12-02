import streamlit as st
import time

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
        page_title="Communication System"
    )
    st.title("Blockchain and Cryptography Communication System")
    st.sidebar.success("Welcome to the secured chat!")

    message = st.text_input('Enter the message for encryption:', type='password')
    if message:
        key = st.slider('Enter your key [1 - 26]:', 1, 26)
    # choice = st.selectbox('Encrypt or Decrypt?', ('Encrypt', 'Decrypt'))
        result = encrypt(message, key)
        result1 = decrypt(result, key)
        time.sleep(5)
        st.write('Result:', result1)

# Run the Streamlit app
if __name__ == '__main__':
    app()

