# pip install flask cryptography Flask-Session

from flask import Flask, request, jsonify
from flask import Flask, request, render_template, redirect, url_for, jsonify
from flask import session
from flask_session import Session
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64
import json
import urllib.parse
import subprocess

app = Flask(__name__)
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_PERMANENT"] = False
app.secret_key = b'Y\xf5Xz\x00\xbf|eQ\x1et \xca\x1a\x60K'
Session(app)
users = {"admin": "admin"}
env = os.environ.copy()
env["flag"] = "U_Hack3d_AES_Congratz"
valid_commands = ["printenv", "ls"]

KEY = os.urandom(16)  # AES-256
BLOCK_SIZE = 16  # AES block size in bytes
IV = os.urandom(BLOCK_SIZE)
def encrypt(plaintext: bytes) -> str:
    # Pad plaintext
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    # Encrypt
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    # Return base64-encoded (URL-safe) ciphertext (no IV included)
    encoded = base64.urlsafe_b64encode(ciphertext).decode('utf-8')
    return encoded

def fix_base64_padding(s: str) -> str:
    return s + '=' * (-len(s) % 4)

def decrypt(encoded_ciphertext: str) -> bytes:
    # Add padding back if needed
    encoded_ciphertext = fix_base64_padding(encoded_ciphertext)
    ciphertext = base64.urlsafe_b64decode(encoded_ciphertext.encode('utf-8'))
    # Ciphertext length check
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Ciphertext length must be a multiple of block size")
    # Decrypt
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    # Unpad
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    return plaintext

def clean_json(input_text):
    whitelist = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-/_. \":{}")
    json_start = False
    json_end = False
    res = ''
    for c in input_text:
        if chr(c) == "{":
            json_start = True
        elif chr(c) == "}":
            json_end = True
        if json_start and chr(c) in whitelist:
            res += chr(c)
        if json_end:
            break
    return res

def logout():
    session.clear()
    return redirect(url_for('home') + '?error=Session is expired.')

@app.route('/shell')
def shell():
    if 'username' in session:
        command = '{"ls":"/"}'
        return render_template('shell.html', valid_commands=valid_commands, command=command, output=encrypt(command.encode()))
    else:
        return logout()
@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('shell'))
    else:
        return render_template('index.html')
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    if users.get(username) == password:
        session['username'] = username
        return redirect(url_for('shell'))
    else:
        return redirect(url_for('home') + '?error=Invalid credentials.')
@app.route('/execute', methods=['POST'])
def execute():
    command_input = request.form.get('command')
    if not command_input:
        return "No command provided."
    elif not 'username' in session:
        return logout()
    else:
        try:
            decrypted_command = decrypt(command_input)
        except Exception as e:
            logout()
            return str(e)
        try:
            if decrypted_command:
                filtered_decrypted_command = clean_json(decrypted_command)
                command_json = json.loads(filtered_decrypted_command)
                command = next(iter(command_json))
                if command in valid_commands:       
                    result = subprocess.run([command, command_json[command]], env=env, shell=False, capture_output=True, text=True, check=False, timeout=5)
                    return jsonify({"result":result.stdout})
                else:
                    return f"Invalid command '{command}'."
            else:
                return "Unexpected error."
        except Exception as e:
            return "Invalid json format."
      
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=False)
