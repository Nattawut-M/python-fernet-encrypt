import json
import os
from cryptography.fernet import Fernet


class Cryptographer:
    """class cryptographer use "Fernet (symmetric encryption)" for encrypt and decrypt data, powered by cryptography"""

    def __init__(
        self, secret_key: str = os.environ.get("PUBLIC_DISARM_SECRET_KEY", None)
    ):
        """create an instance of fernet as an encrypter

        Args:
            secret_key (str):
        """
        if not secret_key:
            raise ValueError("initial secret key for create an instance Cryptographer")

        self.fernet = Fernet(str.encode(secret_key))

    def __generate_secret_key(self) -> bytes:
        """generate a secret key

        Returns:
            bytes: encrypted token
        """
        return Fernet.generate_key()

    def encrypt_data(self, data: str) -> str:
        """encrypt data as a string to string encryptd

        Args:
            data (str): data in string format

        Returns:
            bytes: encrypted token
        """
        encrypted_data = self.fernet.encrypt(data.encode())  # Encrypt the string data
        return encrypted_data.decode()

    def encrypt_data_with_time(self, data: str, time: int = None):
        if not time:
            import time as t

            time = int(t.time())
        return self.fernet.encrypt_at_time(data.encode(), time)

    def decrypt_data(self, encrypted_data: str) -> str:
        """decrypt data

        Args:
            encrypted_data (str): encrypt token

        Returns:
            str: _description_
        """
        decrypted_data = self.fernet.decrypt(encrypted_data)
        return decrypted_data.decode()

def encrypt_option(cipher: Cryptographer):
    while True:
        print()
        alert_setting_id = input("(encrypt) enter alert-setting-id : ")
        try:
            alert_setting_id = int(alert_setting_id)
        except Exception as e:
            print("invalid input, expect number only")
            print("(encrypt) enter 0 to back to menu")

            continue

        if alert_setting_id == 0:
            return

        data = {"alert_setting_id": alert_setting_id}
        data = json.dumps(data)

        token = cipher.encrypt_data(data)
        print(f"(encrypt) token: {token}", sep="\n\n")


def decrypt_option(cipher: Cryptographer):
    while True:
        print()
        try:
            token = input("(decrypt) enter token : ")

            if token == '0':
                return

            data = cipher.decrypt_data(token)
            data = json.loads(data)
            print(f"(decrypt) {data}", sep="\n\n")
        except Exception as e:
            print("something went wrong,", e)
            print("(decrypt) enter 0 to back to menu")

            continue


if __name__ == "__main__":
    PUBLIC_DISARM_SECRET_KEY = os.environ.get("PUBLIC_DISARM_SECRET_KEY", None)

    cipher = Cryptographer()
    print("enter 0 to exit")
    option_choice = None

    while True:
        print("1. generate encrypt token")
        print("2. decrypt token")
        print("0. exit")
        print()

        option_choice = input("(menu) enter option : ")
        try:
            option_choice = int(option_choice)
        except Exception as e:
            print("invalid input, expect number only")
            continue

        if option_choice > 2:
            continue

        if option_choice == 1:
            encrypt_option(cipher)
            continue
        elif option_choice == 2:
            decrypt_option(cipher)
            continue
        elif option_choice == 0:
            exit()
        else:
            print("enter 0 to exit")
            continue
