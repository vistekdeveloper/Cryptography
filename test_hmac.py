import hashlib
import hmac

SECRET_KEY = b"#B5Gh6eEwl$Me7"

with open("menu_today.txt", "rb") as f:
    menu_data = f.read()

hmac_value = hmac.new(SECRET_KEY, menu_data, hashlib.sha256).hexdigest()
print(hmac_value)
