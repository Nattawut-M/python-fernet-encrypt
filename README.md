# python-fernet-encrypt
Python implement class Fernet to encrypt and decrypt

```python
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

```
