from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import hashlib
import random
import math
import json

app = Flask(__name__)
CORS(app)

class RSADigitalSignature:
    """RSA Digital Signature implementation from scratch"""
    
    def __init__(self):
        self.users = {}  # Store user key pairs
    
    def is_prime(self, n):
        """Check if a number is prime using trial division"""
        if n < 2:
            return False
        if n == 2:
            return True
        if n % 2 == 0:
            return False
        
        # Check odd divisors up to sqrt(n)
        for i in range(3, int(math.sqrt(n)) + 1, 2):
            if n % i == 0:
                return False
        return True
    
    def generate_prime(self, bits=10):
        """Generate a random prime number with specified bit length"""
        while True:
            # Generate random number in range
            num = random.randint(2**(bits-1), 2**bits - 1)
            if self.is_prime(num):
                return num
    
    def gcd(self, a, b):
        """Calculate Greatest Common Divisor using Euclidean algorithm"""
        while b:
            a, b = b, a % b
        return a
    
    def extended_gcd(self, a, b):
        """Extended Euclidean Algorithm to find modular inverse"""
        if a == 0:
            return b, 0, 1
        
        gcd, x1, y1 = self.extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        
        return gcd, x, y
    
    def mod_inverse(self, e, phi_n):
        """Calculate modular multiplicative inverse"""
        gcd, x, y = self.extended_gcd(e, phi_n)
        if gcd != 1:
            raise ValueError("Modular inverse does not exist")
        return (x % phi_n + phi_n) % phi_n
    
    def power_mod(self, base, exp, mod):
        """Fast modular exponentiation using binary method"""
        result = 1
        base = base % mod
        
        while exp > 0:
            # If exp is odd, multiply base with result
            if exp % 2 == 1:
                result = (result * base) % mod
            
            # exp must be even now
            exp = exp >> 1  # exp = exp / 2
            base = (base * base) % mod
        
        return result
    
    def generate_keypair(self, username, bits=10):
        """Generate RSA public and private key pair for digital signatures"""
        print(f"=== Generating RSA Keys for {username} ===")
        
        # Step 1: Generate two distinct prime numbers
        p = self.generate_prime(bits)
        q = self.generate_prime(bits)
        
        # Ensure p and q are different
        while p == q:
            q = self.generate_prime(bits)
        
        print(f"Prime p = {p}")
        print(f"Prime q = {q}")
        
        # Step 2: Calculate n = p * q
        n = p * q
        print(f"n = p × q = {p} × {q} = {n}")
        
        # Step 3: Calculate Euler's totient function φ(n) = (p-1)(q-1)
        phi_n = (p - 1) * (q - 1)
        print(f"φ(n) = (p-1)(q-1) = ({p}-1)({q}-1) = {phi_n}")
        
        # Step 4: Choose e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1
        # For digital signatures, we often use smaller e values
        e = 65537
        
        # If e is too large or not coprime, find a suitable e
        if e >= phi_n or self.gcd(e, phi_n) != 1:
            e = 3
            while e < phi_n and self.gcd(e, phi_n) != 1:
                e += 2
        
        print(f"Public exponent e = {e}")
        
        # Step 5: Calculate d, the modular multiplicative inverse of e
        d = self.mod_inverse(e, phi_n)
        print(f"Private exponent d = {d}")
        
        # Store keys for the user
        self.users[username] = {
            'public_key': {'n': n, 'e': e},
            'private_key': {'n': n, 'd': d},
            'key_details': {
                'p': p, 'q': q, 'phi_n': phi_n
            }
        }
        
        return {
            'username': username,
            'public_key': {'n': n, 'e': e},
            'private_key': {'n': n, 'd': d},
            'key_generation_details': {
                'p': p, 'q': q, 'phi_n': phi_n, 'e': e, 'd': d
            }
        }
    
    def hash_message(self, message):
        """Create SHA-256 hash of the message"""
        # Convert message to bytes and hash
        message_bytes = message.encode('utf-8')
        hash_object = hashlib.sha256(message_bytes)
        hash_hex = hash_object.hexdigest()
        
        # Convert hex hash to integer for RSA operations
        hash_int = int(hash_hex, 16)
        
        return {
            'original_message': message,
            'hash_hex': hash_hex,
            'hash_int': hash_int,
            'hash_length': len(hash_hex)
        }
    
    def sign_message(self, username, message):
        """Sign a message using the user's private key"""
        if username not in self.users:
            raise ValueError(f"User {username} not found. Generate keys first.")
        
        print(f"=== Digital Signature Process for {username} ===")
        
        # Step 1: Hash the message
        hash_info = self.hash_message(message)
        hash_int = hash_info['hash_int']
        
        print(f"Original Message: '{message}'")
        print(f"SHA-256 Hash: {hash_info['hash_hex']}")
        print(f"Hash as Integer: {hash_int}")
        
        # Step 2: Get user's private key
        private_key = self.users[username]['private_key']
        n = private_key['n']
        d = private_key['d']
        
        print(f"Private Key: n={n}, d={d}")
        
        # Step 3: Reduce hash if it's larger than n
        if hash_int >= n:
            # Take modulo to fit within key size
            hash_int = hash_int % n
            print(f"Hash reduced to fit key size: {hash_int}")
        
        # Step 4: Create digital signature using RSA private key
        # Signature = hash^d mod n
        signature = self.power_mod(hash_int, d, n)
        
        print(f"Digital Signature: {hash_int}^{d} mod {n} = {signature}")
        
        return {
            'username': username,
            'original_message': message,
            'message_hash': hash_info,
            'signature': signature,
            'signing_details': {
                'private_key_n': n,
                'private_key_d': d,
                'hash_before_signing': hash_int
            }
        }
    
    def verify_signature(self, username, message, signature):
        """Verify a digital signature using the user's public key"""
        if username not in self.users:
            raise ValueError(f"User {username} not found.")
        
        print(f"=== Signature Verification Process ===")
        
        # Step 1: Hash the received message
        hash_info = self.hash_message(message)
        received_hash = hash_info['hash_int']
        
        print(f"Received Message: '{message}'")
        print(f"SHA-256 Hash of Received Message: {hash_info['hash_hex']}")
        print(f"Hash as Integer: {received_hash}")
        
        # Step 2: Get user's public key
        public_key = self.users[username]['public_key']
        n = public_key['n']
        e = public_key['e']
        
        print(f"Public Key: n={n}, e={e}")
        print(f"Received Signature: {signature}")
        
        # Step 3: Reduce hash if it's larger than n (same as in signing)
        if received_hash >= n:
            received_hash = received_hash % n
            print(f"Hash reduced to fit key size: {received_hash}")
        
        # Step 4: Decrypt the signature using RSA public key
        # Decrypted = signature^e mod n
        decrypted_hash = self.power_mod(signature, e, n)
        
        print(f"Decrypted Signature: {signature}^{e} mod {n} = {decrypted_hash}")
        
        # Step 5: Compare decrypted hash with computed hash
        is_valid = (decrypted_hash == received_hash)
        
        print(f"Hash from Message: {received_hash}")
        print(f"Hash from Signature: {decrypted_hash}")
        print(f"Signature Valid: {is_valid}")
        
        return {
            'username': username,
            'message': message,
            'signature': signature,
            'is_valid': is_valid,
            'verification_details': {
                'computed_hash': received_hash,
                'decrypted_hash': decrypted_hash,
                'public_key_n': n,
                'public_key_e': e,
                'message_hash_info': hash_info
            }
        }

# Initialize RSA system
rsa_system = RSADigitalSignature()

@app.route('/')
def index():
    """Serve the main HTML page"""
    return render_template('index.html')

@app.route('/api/generate-keys', methods=['POST'])
def generate_keys():
    """Generate RSA key pair for a user"""
    try:
        data = request.get_json()
        username = data.get('username', 'DefaultUser')
        bits = data.get('bits', 10)  # Small for demo, use 1024+ in production
        
        key_info = rsa_system.generate_keypair(username, bits)
        
        return jsonify({
            'success': True,
            'data': key_info,
            'message': f'RSA key pair generated successfully for {username}'
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/api/sign-message', methods=['POST'])
def sign_message():
    """Sign a message with user's private key"""
    try:
        data = request.get_json()
        username = data.get('username')
        message = data.get('message')
        
        if not username or not message:
            return jsonify({
                'success': False,
                'error': 'Username and message are required'
            }), 400
        
        signature_info = rsa_system.sign_message(username, message)
        
        return jsonify({
            'success': True,
            'data': signature_info,
            'message': 'Message signed successfully'
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/api/verify-signature', methods=['POST'])
def verify_signature():
    """Verify a digital signature"""
    try:
        data = request.get_json()
        username = data.get('username')
        message = data.get('message')
        signature = data.get('signature')
        
        if not username or not message or signature is None:
            return jsonify({
                'success': False,
                'error': 'Username, message, and signature are required'
            }), 400
        
        verification_info = rsa_system.verify_signature(username, message, int(signature))
        
        return jsonify({
            'success': True,
            'data': verification_info,
            'message': 'Signature verification completed'
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/api/get-users', methods=['GET'])
def get_users():
    """Get list of users with their public keys"""
    try:
        users_info = {}
        for username, user_data in rsa_system.users.items():
            users_info[username] = {
                'username': username,
                'public_key': user_data['public_key']
            }
        
        return jsonify({
            'success': True,
            'data': users_info
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/api/get-user/<username>', methods=['GET'])
def get_user(username):
    """Get specific user's key information"""
    try:
        if username not in rsa_system.users:
            return jsonify({
                'success': False,
                'error': f'User {username} not found'
            }), 404
        
        user_data = rsa_system.users[username]
        return jsonify({
            'success': True,
            'data': {
                'username': username,
                'public_key': user_data['public_key'],
                'has_private_key': True,  # Don't expose private key
                'key_details': user_data['key_details']
            }
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

if __name__ == '__main__':
    # Create templates directory and basic HTML if it doesn't exist
    import os
    if not os.path.exists('templates'):
        os.makedirs('templates')
    
    print("🔐 RSA Digital Signature System Starting...")
    print("📊 Available Endpoints:")
    print("   GET  /                     - Main interface")
    print("   POST /api/generate-keys    - Generate RSA key pair")
    print("   POST /api/sign-message     - Sign a message")
    print("   POST /api/verify-signature - Verify a signature")
    print("   GET  /api/get-users        - List all users")
    print("   GET  /api/get-user/<name>  - Get user details")
    print("\n🚀 Server running on http://localhost:5000")
    
    app.run(debug=True, host='0.0.0.0', port=5000)