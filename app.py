from flask import Flask, render_template, request
from crypto_utils import *
import base64

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    result = ''
    key = ''
    iv = ''
    private_key_pem = ''
    public_key_pem = ''

    if request.method == 'POST':
        mode = request.form['mode']
        algorithm = request.form['algorithm']
        message = request.form['message']

        if algorithm == 'aes128':
            if mode == 'encrypt':
                key = generate_symmetric_key()
                result = encrypt_symmetric(key, message)
                key = key.decode()
            else:
                key = request.form['key']
                result = decrypt_symmetric(key.encode(), message)

        elif algorithm == 'aes256':
            if mode == 'encrypt':
                key, iv = generate_aes256_key_iv()
                result = encrypt_aes256(message, key, iv)
            else:
                key = request.form['key']
                iv = request.form['iv']
                result = decrypt_aes256(message, key, iv)

        elif algorithm == 'rsa':
            if mode == 'encrypt':
                private_key, public_key = generate_asymmetric_keys()
                encrypted = encrypt_asymmetric(public_key, message)
                result = base64.b64encode(encrypted).decode()
                private_key_pem, public_key_pem = serialize_keys(private_key, public_key)
            else:
                private_key_pem = request.form['private_key']
                encrypted_data = base64.b64decode(message)
                private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
                result = decrypt_asymmetric(private_key, encrypted_data)

        elif algorithm == 'sha256':
            result = hash_sha256(message)

        elif algorithm == 'sha512':
            result = hash_sha512(message)

        elif algorithm == 'base64':
            if mode == 'encrypt':
                result = base64_encode(message)
            else:
                result = base64_decode(message)

    return render_template('index.html', result=result, key=key, iv=iv,
                           private_key=private_key_pem, public_key=public_key_pem)

if __name__ == '__main__':
    app.run(debug=True)
