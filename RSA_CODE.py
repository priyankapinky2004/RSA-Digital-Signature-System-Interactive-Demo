import random
import math

class RSAAlgorithm:
    def _init_(self):
        """Initialize RSA Algorithm class"""
        self.public_key = None
        self.private_key = None
    
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
    
    def generate_prime(self, bits=8):
        """Generate a random prime number with specified bit length"""
        while True:
            # Generate random number in range
            num = random.randint(2*(bits-1), 2*bits - 1)
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
    
    def generate_keypair(self, bits=8):
        """Generate RSA public and private key pair"""
        print("=== RSA Key Generation Process ===")
        
        # Step 1: Generate two distinct prime numbers
        print("Step 1: Generating prime numbers...")
        p = self.generate_prime(bits)
        q = self.generate_prime(bits)
        
        # Ensure p and q are different
        while p == q:
            q = self.generate_prime(bits)
        
        print(f"Prime p = {p}")
        print(f"Prime q = {q}")
        
        # Step 2: Calculate n = p * q
        n = p * q
        print(f"Step 2: n = p × q = {p} × {q} = {n}")
        
        # Step 3: Calculate Euler's totient function φ(n) = (p-1)(q-1)
        phi_n = (p - 1) * (q - 1)
        print(f"Step 3: φ(n) = (p-1)(q-1) = ({p}-1)({q}-1) = {phi_n}")
        
        # Step 4: Choose e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1
        print("Step 4: Choosing public exponent e...")
        e = 65537  # Common choice for e
        
        # If e is too large or not coprime, find a suitable e
        if e >= phi_n or self.gcd(e, phi_n) != 1:
            e = 3
            while e < phi_n and self.gcd(e, phi_n) != 1:
                e += 2
        
        print(f"Public exponent e = {e}")
        print(f"Verification: gcd({e}, {phi_n}) = {self.gcd(e, phi_n)}")
        
        # Step 5: Calculate d, the modular multiplicative inverse of e
        print("Step 5: Calculating private exponent d...")
        d = self.mod_inverse(e, phi_n)
        print(f"Private exponent d = {d}")
        print(f"Verification: (e × d) mod φ(n) = ({e} × {d}) mod {phi_n} = {(e * d) % phi_n}")
        
        # Store keys
        self.public_key = (n, e)
        self.private_key = (n, d)
        
        print(f"\n=== Generated Keys ===")
        print(f"Public Key (n, e) = ({n}, {e})")
        print(f"Private Key (n, d) = ({n}, {d})")
        
        return self.public_key, self.private_key
    
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
    
    def encrypt(self, message, public_key):
        """Encrypt message using RSA public key"""
        n, e = public_key
        
        if isinstance(message, str):
            # Convert string to list of ASCII values
            message_nums = [ord(char) for char in message]
        else:
            message_nums = [message]
        
        encrypted = []
        print(f"\n=== Encryption Process ===")
        print(f"Public Key: (n={n}, e={e})")
        
        for i, num in enumerate(message_nums):
            if num >= n:
                raise ValueError(f"Message value {num} is too large for key size")
            
            # Encrypt: c = m^e mod n
            cipher = self.power_mod(num, e, n)
            encrypted.append(cipher)
            
            if isinstance(message, str):
                print(f"'{message[i]}' (ASCII {num}) -> {num}^{e} mod {n} = {cipher}")
            else:
                print(f"Message {num} -> {num}^{e} mod {n} = {cipher}")
        
        return encrypted
    
    def decrypt(self, ciphertext, private_key):
        """Decrypt ciphertext using RSA private key"""
        n, d = private_key
        
        decrypted = []
        print(f"\n=== Decryption Process ===")
        print(f"Private Key: (n={n}, d={d})")
        
        for i, cipher in enumerate(ciphertext):
            # Decrypt: m = c^d mod n
            message = self.power_mod(cipher, d, n)
            decrypted.append(message)
            print(f"Cipher {cipher} -> {cipher}^{d} mod {n} = {message}")
        
        return decrypted
    
    def encrypt_message(self, message, public_key):
        """Encrypt a string message"""
        encrypted = self.encrypt(message, public_key)
        return encrypted
    
    def decrypt_message(self, ciphertext, private_key):
        """Decrypt to get original string message"""
        decrypted_nums = self.decrypt(ciphertext, private_key)
        message = ''.join([chr(num) for num in decrypted_nums])
        return message

class SecureMessagingDemo:
    """Interactive demo for secure messaging between two users"""
    
    def _init_(self):
        self.rsa = RSAAlgorithm()
        self.users = {}
    
    def create_user(self, username, bits=8):
        """Create a new user with RSA key pair"""
        print(f"\n{'='*50}")
        print(f"Creating User: {username}")
        print(f"{'='*50}")
        
        user_rsa = RSAAlgorithm()
        public_key, private_key = user_rsa.generate_keypair(bits)
        
        self.users[username] = {
            'rsa': user_rsa,
            'public_key': public_key,
            'private_key': private_key
        }
        
        return public_key, private_key
    
    def send_secure_message(self, sender, receiver, message):
        """Send encrypted message from sender to receiver"""
        print(f"\n{'='*60}")
        print(f"SECURE MESSAGE: {sender} → {receiver}")
        print(f"{'='*60}")
        
        if sender not in self.users or receiver not in self.users:
            print("Error: Both users must be created first!")
            return None
        
        # Get receiver's public key for encryption
        receiver_public_key = self.users[receiver]['public_key']
        sender_rsa = self.users[sender]['rsa']
        
        print(f"Original Message: '{message}'")
        print(f"Using {receiver}'s public key for encryption...")
        
        # Encrypt message
        encrypted_message = sender_rsa.encrypt_message(message, receiver_public_key)
        
        print(f"Encrypted Message: {encrypted_message}")
        
        return encrypted_message
    
    def receive_secure_message(self, receiver, encrypted_message):
        """Decrypt received message using receiver's private key"""
        print(f"\n{'='*60}")
        print(f"MESSAGE DECRYPTION BY: {receiver}")
        print(f"{'='*60}")
        
        if receiver not in self.users:
            print("Error: Receiver not found!")
            return None
        
        # Get receiver's private key for decryption
        receiver_private_key = self.users[receiver]['private_key']
        receiver_rsa = self.users[receiver]['rsa']
        
        print(f"Encrypted Message Received: {encrypted_message}")
        print(f"Using {receiver}'s private key for decryption...")
        
        # Decrypt message
        decrypted_message = receiver_rsa.decrypt_message(encrypted_message, receiver_private_key)
        
        print(f"Decrypted Message: '{decrypted_message}'")
        
        return decrypted_message

def main():
    """Main function to demonstrate RSA algorithm"""
    print("RSA ALGORITHM IMPLEMENTATION FROM SCRATCH")
    print("="*50)
    
    # Create secure messaging demo
    demo = SecureMessagingDemo()
    
    print("\n🔐 SECURE MESSAGING SYSTEM DEMO")
    print("Demonstrating RSA encryption between two users")
    
    # Create two users
    print("\n1️⃣ Creating User Alice...")
    alice_public, alice_private = demo.create_user("Alice", bits=8)
    
    print("\n2️⃣ Creating User Bob...")
    bob_public, bob_private = demo.create_user("Bob", bits=8)
    
    # Demo 1: Alice sends message to Bob
    print("\n3️⃣ DEMO 1: Alice sends secure message to Bob")
    message1 = "HELLO"
    encrypted_msg1 = demo.send_secure_message("Alice", "Bob", message1)
    
    if encrypted_msg1:
        decrypted_msg1 = demo.receive_secure_message("Bob", encrypted_msg1)
        print(f"\n✅ Communication successful!")
        print(f"   Original: '{message1}' → Decrypted: '{decrypted_msg1}'")
        print(f"   Match: {message1 == decrypted_msg1}")
    
    # Demo 2: Bob sends message to Alice
    print("\n4️⃣ DEMO 2: Bob sends secure message to Alice")
    message2 = "HI"
    encrypted_msg2 = demo.send_secure_message("Bob", "Alice", message2)
    
    if encrypted_msg2:
        decrypted_msg2 = demo.receive_secure_message("Alice", encrypted_msg2)
        print(f"\n✅ Communication successful!")
        print(f"   Original: '{message2}' → Decrypted: '{decrypted_msg2}'")
        print(f"   Match: {message2 == decrypted_msg2}")
    
    # Show key exchange concept
    print(f"\n5️⃣ KEY EXCHANGE SUMMARY")
    print(f"{'='*40}")
    print(f"Alice's Keys:")
    print(f"  Public Key:  {alice_public} (shared with Bob)")
    print(f"  Private Key: {alice_private} (kept secret)")
    print(f"\nBob's Keys:")
    print(f"  Public Key:  {bob_public} (shared with Alice)")
    print(f"  Private Key: {bob_private} (kept secret)")
    
    print(f"\n6️⃣ SECURITY PRINCIPLE")
    print(f"{'='*40}")
    print("✅ Alice encrypts with Bob's PUBLIC key")
    print("✅ Bob decrypts with his own PRIVATE key")
    print("✅ Only Bob can decrypt messages meant for him")
    print("✅ Alice's private key remains secure")

if _name_ == "_main_":
    main()