import random
import string
import hashlib
import time
from datetime import datetime, timedelta
from cryptography.fernet import Fernet # type: ignore

# Generate a key for encryption and decryption
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Dummy user data with hashed passwords and encrypted security answers
users = {
    "user1": {
        "password": hashlib.sha256("password123".encode()).hexdigest(),
        "security_question": "What is your pet's name?",
        "security_answer": cipher_suite.encrypt(b"Fluffy").decode(),
        "failed_attempts": 0,
        "account_locked_until": None
    },
    "user2": {
        "password": hashlib.sha256("mypassword".encode()).hexdigest(),
        "security_question": "What is your favorite color?",
        "security_answer": cipher_suite.encrypt(b"Blue").decode(),
        "failed_attempts": 0,
        "account_locked_until": None
    }
}

# Logging dictionary
auth_log = []

# Function to generate OTP
def generate_otp(length=6):
    otp = ''.join(random.choices(string.digits, k=length))
    otp_expiry = datetime.now() + timedelta(minutes=5)
    return otp, otp_expiry

# Hashing function
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Password strength checker
def is_strong_password(password):
    if (len(password) >= 8 and
        any(char.isdigit() for char in password) and
        any(char.isupper() for char in password) and
        any(char.islower() for char in password) and
        any(char in string.punctuation for char in password)):
        return True
    return False

# First Level: User authentication
def authenticate_user(username, password):
    if username in users:
        user = users[username]
        
        # Check if the account is locked
        if user["account_locked_until"] and datetime.now() < user["account_locked_until"]:
            return False, "Account is locked. Try again later."

        # Verify the password
        if user["password"] == hash_password(password):
            user["failed_attempts"] = 0  # Reset failed attempts on successful login
            return True, "First level authentication successful."
        else:
            user["failed_attempts"] += 1
            if user["failed_attempts"] >= 3:
                user["account_locked_until"] = datetime.now() + timedelta(minutes=15)
                return False, "Too many failed attempts. Account locked for 15 minutes."
            return False, "Incorrect password."
    return False, "Username not found."

# Second Level: Security question verification
def verify_security_question(username, answer):
    decrypted_answer = cipher_suite.decrypt(users[username]["security_answer"].encode()).decode()
    if decrypted_answer.lower() == answer.lower():
        return True
    return False

# Third Level: OTP verification
def verify_otp(generated_otp, user_otp, otp_expiry):
    if datetime.now() > otp_expiry:
        return False, "OTP has expired."
    if generated_otp == user_otp:
        return True, "Third level authentication successful. Access granted."
    return False, "Incorrect OTP."

# Simulated biometric check
def biometric_check():
    # Simulate a biometric check with a random outcome
    return random.choice([True, False])

# Logging function
def log_attempt(username, result, details=""):
    auth_log.append({
        "username": username,
        "result": result,
        "details": details,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })

# Main function to run the three-level authentication system
def main():
    username = input("Enter username: ")
    password = input("Enter password: ")

    # First Level Verification
    success, message = authenticate_user(username, password)
    log_attempt(username, success, message)
    print(message)
    if not success:
        return

    # Second Level Verification
    security_question = users[username]["security_question"]
    print(security_question)
    security_answer = input("Answer: ")

    if verify_security_question(username, security_answer):
        print("Second level authentication successful.")
        log_attempt(username, True, "Second level authentication successful.")
        
        # Third Level Verification
        generated_otp, otp_expiry = generate_otp()
        print(f"Generated OTP: {generated_otp}")  # In a real-world scenario, this would be sent via SMS or email
        user_otp = input("Enter OTP: ")

        success, message = verify_otp(generated_otp, user_otp, otp_expiry)
        log_attempt(username, success, message)
        print(message)
        
        if success:
            # Simulated biometric check
            if biometric_check():
                print("Biometric check successful. Access granted.")
                log_attempt(username, True, "Biometric check successful.")
            else:
                print("Biometric check failed. Access denied.")
                log_attempt(username, False, "Biometric check failed.")
    else:
        print("Incorrect answer to the security question. Access denied.")
        log_attempt(username, False, "Incorrect answer to the security question.")

if __name__ == "__main__":
    main()
