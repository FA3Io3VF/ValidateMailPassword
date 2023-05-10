import string
import requests
import hashlib
import os
import email_validator
from password_validator import PasswordValidator

DOMAINS_FILE = "valid_domains.txt"
API_KEY = "YOUR_API_KEY" 

COMMON_PASSWORDS_API = "https://api.pwnedpasswords.com/range/"
COMMON_PASSWORDS_THRESHOLD = 100  

def is_common_password(password: str) -> bool:
    sha1_password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1_password[:5]
    suffix = sha1_password[5:]
    try:
        response = requests.get(COMMON_PASSWORDS_API + prefix)
        if response.status_code != 200:
            raise Exception("Response code was not 200")
        for line in response.text.splitlines():
            if suffix in line:
                count = int(line.split(":")[1])
                if count >= COMMON_PASSWORDS_THRESHOLD:
                    return True
    except Exception as e:
        print("Could not access common password API: ", e)
        return False
    return False
 

def is_valid_password(password: str) -> bool:
    if len(password) < 6:
        return False
    has_symbol = False
    has_number = False
    for char in password:
        if char in string.punctuation:
            has_symbol = True
        elif char.isdigit():
            has_number = True
    if not has_symbol or not has_number:
        return False

    if is_common_password(password):
        return False

    password_schema = PasswordValidator()
    password_schema.min_length = 6
    password_schema.has_numbers()
    password_schema.has_symbols()

    if not password_schema.validate(password):
        return False

    return True


def validate_email(email: str) -> bool:
    if os.path.isfile(DOMAINS_FILE):
        with open(DOMAINS_FILE, "r") as f:
            valid_domains = f.read().splitlines()
            domain = email.split("@")[-1]
            if domain not in valid_domains:
                return False

    # Check if email is valid according to email-validator
    try:
        email_validator.validate_email(email)
    except email_validator.EmailNotValidError:
        return False
    
    # Check email with API if available
    if API_KEY:
        try:
            response = requests.get(f"https://api.email-validator.net/api/verify?EmailAddress={email}&APIKey={API_KEY}")
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "valid":
                    return True
        except requests.exceptions.RequestException:
            pass
    
    # Check email with email-validator again as a fallback
    try:
        email_validator.validate_email(email, check_deliverability=False)
        return True
    except email_validator.EmailNotValidError:
        return False
    
