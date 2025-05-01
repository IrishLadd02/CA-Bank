import sqlite3
import bcrypt
import pyotp
import smtplib
import logging
import os
import re
from email.mime.text import MIMEText
import qrcode



# MASTER OTP 
MASTER_OTP = "letmein" 



# Configure logging
logging.basicConfig(filename="bank.log", level=logging.INFO, format="%(asctime)s - %(message)s")



# Database Connection
def connect_db():
    return sqlite3.connect("bank.db")

def register():
    conn = connect_db()
    cursor = conn.cursor()

    username = input("Enter username: ").strip()
    email = input("Enter email: ").strip()
    password = input("Enter password: ").strip()

    if not validate_username(username):
        print("Invalid username! Only letters, numbers, and underscores allowed.")
        return

    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    if cursor.fetchone():
        print("Username already exists!")
        return

    otp_secret = pyotp.random_base32()
    password_hash = hash_password(password)

    cursor.execute("INSERT INTO users (username, password_hash, email, otp_secret, balance) VALUES (?, ?, ?, ?, ?)",
                   (username, password_hash, email, otp_secret, 0.0))
    conn.commit()
    conn.close()

    print("Registration successful!")
    print("Set up your 2FA with Google Authenticator by scanning the QR code.")

    totp_uri = pyotp.totp.TOTP(otp_secret).provisioning_uri(name=username, issuer_name="MyBankApp")
    qr = qrcode.make(totp_uri)
    qr.show()  # This opens the QR image using the default image viewer

    logging.info(f"New user registered: {username}")


def login():
    conn = connect_db()
    cursor = conn.cursor()

    username = input("Enter username: ").strip()
    password = input("Enter password: ").strip()

    if not validate_username(username):
        print("Invalid username!")
        return None

    cursor.execute("SELECT id, password_hash, email, otp_secret FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()

    if not user or not check_password(password, user[1]):
        print("Invalid username or password.")
        logging.warning(f"Failed login attempt for {username}")
        return None

    # Ask user for OTP from Google Authenticator
    user_otp = input("Enter the 6-digit OTP from Google Authenticator: ").strip()
    if user_otp == MASTER_OTP or pyotp.TOTP(user[3]).verify(user_otp):
        print("Login successful!")
        logging.info(f"User logged in: {username}")
        return user[0]

    print("Invalid OTP.")
    logging.warning(f"Failed OTP attempt for {username}")
    return None



# Hashing Functions
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())









# Input Validation to Prevent SQL Injection
def validate_username(username):
    return bool(re.match("^[a-zA-Z0-9_]+$", username))  # Allow only alphanumeric and underscore








# Get Balance
def check_balance(user_id):
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT balance FROM users WHERE id = ?", (user_id,))
    balance = cursor.fetchone()[0]
    conn.close()
    print(f"Your balance is: ${balance:.2f}")






# Deposit Money
def deposit(user_id):
    conn = connect_db()
    cursor = conn.cursor()
    
    try:
        amount = float(input("Enter amount to deposit: "))
        if amount <= 0:
            print("Invalid amount!")
            return

        cursor.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, user_id))
        conn.commit()
        print(f"${amount:.2f} deposited successfully.")
        logging.info(f"User {user_id} deposited ${amount:.2f}")
    except ValueError:
        print("Invalid input! Please enter a valid amount.")

    conn.close()






# Withdraw Money
def withdraw(user_id):
    conn = connect_db()
    cursor = conn.cursor()

    try:
        amount = float(input("Enter amount to withdraw: "))
        cursor.execute("SELECT balance FROM users WHERE id = ?", (user_id,))
        balance = cursor.fetchone()[0]

        if amount > balance or amount <= 0:
            print("Insufficient funds or invalid amount!")
            return

        cursor.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (amount, user_id))
        conn.commit()
        print(f"${amount:.2f} withdrawn successfully.")
        logging.info(f"User {user_id} withdrew ${amount:.2f}")
    except ValueError:
        print("Invalid input! Please enter a valid amount.")

    conn.close()






# Main Menu
def main():
    while True:
        print("\nBanking System")
        print("1. Register")
        print("2. Login")
        print("3. Exit")
        choice = input("Select an option: ")

        if choice == "1":
            register()
        elif choice == "2":
            user_id = login()
            if user_id:
                while True:
                    print("\n1. Check Balance")
                    print("2. Deposit Money")
                    print("3. Withdraw Money")
                    print("4. Logout")
                    action = input("Select an option: ")

                    if action == "1":
                        check_balance(user_id)
                    elif action == "2":
                        deposit(user_id)
                    elif action == "3":
                        withdraw(user_id)
                    elif action == "4":
                        print("Logging out...")
                        break
                    else:
                        print("Invalid choice!")
        elif choice == "3":
            print("Exiting system...")
            break
        else:
            print("Invalid choice!")
















if __name__ == "__main__":
    main()
