import asyncio
import sys
import hashlib
import os
from cryptography.fernet import Fernet  # type: ignore
from cryptography.fernet import InvalidToken  # type: ignore
import hmac
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# Use a predefined key (must be a URL-safe base64-encoded 32-byte key)
predefined_key = b'MY9Kx7thDF9T4qCj6kP6bZjNa9yL8h9DUCqkUG4NcYQ='
cipher_suite = Fernet(predefined_key)

hmac_key = b'your_secret_hmac_key'

# Generate RSA key pair for digital signatures
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()


def sign_message(message):
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_signature(message, signature):
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


async def load_messages(username):
    """
    Load messages for a user from a file.
    :param username: The username of the user.
    :return: A list of messages for the user.
    """
    try:
        with open(f"{username.lower()}.txt", "r") as file:
            messages = file.readlines()
        messages = [msg.strip() for msg in messages]
        if len(messages) == 1 and (messages[0] == "\n" or messages[0] == ""):
            messages = []
        print(f"Loaded {len(messages)} messages for user {username.capitalize()}")
        return messages
    except FileNotFoundError:
        print(f"No messages found for user {username.capitalize()}")
        return []


async def save_message(recipient, sender, message):
    """
    Save a message from a sender to a recipient.
    :param recipient: The username of the recipient.
    :param sender: The username of the sender.
    :param message: The message to be saved.
    """
    with open(f"{recipient.lower()}.txt", "a") as file:
        file.write(f"{sender.lower()}|{message}\n")
    print(f"Message saved from {sender.lower()} to {recipient.lower()}")


async def send_response(writer, response):
    """
    Send a response to the client.
    :param writer: The writer object for the client connection.
    :param response: The response to be sent.
    """
    encrypted_message = cipher_suite.encrypt((response + '\n').encode())
    hmac_signature = hmac.new(hmac_key, encrypted_message, hashlib.sha256).hexdigest()
    writer.write(f"{encrypted_message.decode()}|{hmac_signature}\n".encode())
    await writer.drain()


async def handle_login(writer, username, password):
    """
    Handle the LOGIN command.
    :param writer: The writer object for the client connection.
    :param username: The username provided by the client.
    :return: The username if valid, None otherwise.
    """
    
    if ' ' in username:
        print(f"Invalid username: {username}")
        await send_response(writer, "Invalid username\n")
        return None
    if ' ' in password:
        print(f"Invalid password: {password}")
        await send_response(writer, "Invalid password\n")
        return None
    
    user_found = False
    try:
        with open('users.txt', 'r') as file:
            for line in file:
                if line.split()[0].lower() == username.lower():
                    user_found = True
                    salt_hex = line.split()[1]
                    password_hash = line.split()[2]
                    break
    except FileNotFoundError:
        print("User file not found - no registered users")
        await send_response(writer, "Invalid username\n")
        return None
            
    if not user_found:
        print(f"User {username.capitalize()} not found")
        await send_response(writer, "Invalid username\n")
        return None

    if not verify_password(salt_hex, password_hash, password):
        print(f"Invalid password for user {username.capitalize()}")
        await send_response(writer, "Invalid password\n")
        return None
    
    print(f"User {username.capitalize()} logged in")
    messages = await load_messages(username.lower())
    await send_response(writer, f"{len(messages)}\n")
    return username.capitalize()


async def handle_register(writer, username, password):
    """
    Handle the REGISTER command.
    :param writer: The writer object for the client connection.
    :param username: The username provided by the client.
    :param password: The password provided by the client.
    """
    if ' ' in username:
        print(f"Invalid username: {username}")
        await send_response(writer, "Invalid username\n")
        return
    if ' ' in password:
        print(f"Invalid password: {password}")
        await send_response(writer, "Invalid password\n")
        return
    try:
        with open("users.txt", "r") as file:
            for line in file:
                if line.lower() == username.lower():
                    print(f"Username {username.capitalize()} already exists")
                    await send_response(writer, "Username already exists\n")
                    return
    except FileNotFoundError:
        pass
    
    salt_hex, password_hash = hash_password(password)
    
    with open("users.txt", "a") as file:
        file.write(f"{username.lower()} {salt_hex} {password_hash}\n")
    print(f"User {username.capitalize()} registered")
    await send_response(writer, "REGISTERED\n")


def hash_password(password):
    salt = os.urandom(32)
    hashed_password = hashlib.sha256(salt + password.encode()).hexdigest()
    return salt.hex(), hashed_password


def verify_password(stored_salt, stored_hashed_password, provided_password):
    salt = bytes.fromhex(stored_salt)
    hashed_password = hashlib.sha256(salt + provided_password.encode()).hexdigest()
    return hashed_password == stored_hashed_password


async def handle_compose(writer, username, recipient, message):
    signature = sign_message(message.encode())
    await save_message(recipient.lower(), username.lower(), f"{message}|{signature.hex()}")
    await send_response(writer, "MESSAGE SENT\n")
    print(f"User {username.capitalize()} left a message to {recipient.capitalize()}")


async def handle_read(writer, username):
    """
    Handle the READ command.
    :param writer: The writer object for the client connection.
    :param username: The username of the user reading messages.
    """
    messages = await load_messages(username.lower())
    if not messages:
        print(f"No messages found for user {username.capitalize()}")
        await send_response(writer, "READ ERROR\n")
    else:
        sender, message, signature = messages[0].split("|", 2)
        if verify_signature(message.encode(), bytes.fromhex(signature)):
            print(f"User {username.capitalize()} is reading a message from {sender.capitalize()}: {message}")
            await send_response(writer, f"{sender.capitalize()}\n")
            await send_response(writer, f"{message}\n")
            print(f"Message sent to user {username.capitalize()}")
            print(f"{len(messages)-1} messages left for user {username.capitalize()}")
            if len(messages) > 1:
                messages = messages[1:]
                with open(f"{username.lower()}.txt", "w") as file:
                    file.write("\n".join(messages))
                    file.write("\n")
            else:
                # Clear the file
                with open(f"{username.lower()}.txt", "w") as file:
                    file.write("\n")
        else:
            print(f"Invalid signature for message from {sender.capitalize()}")
            await send_response(writer, "Invalid message signature\n")


async def handle_client(reader, writer):
    """ Handle communication with a client.
    :param reader: The reader object for the client connection.
    :param writer: The writer object for the client connection.
    """
    addr = writer.get_extra_info('peername')
    print(f"New client connected: {addr}")
    username = None
    while True:
        try:
            data = await reader.readline()
            encrypted_data, received_hmac = data.decode().strip().split('|')
            encrypted_data_bytes = encrypted_data.encode()
            calculated_hmac = hmac.new(hmac_key, encrypted_data_bytes, hashlib.sha256).hexdigest()
            
            if calculated_hmac != received_hmac:
                print(f"Message integrity check failed for client {addr}. Message may have been tampered with.")
                await send_response(writer, "Invalid HMAC signature\n")
                continue
            
            data = cipher_suite.decrypt(encrypted_data_bytes).decode().strip()
            print(f"Decrypted data from {addr}: {data}")
        except InvalidToken:
            print(f"Invalid token received from {addr}")
            await send_response(writer, "Invalid token\n")
        except ValueError:
            print("Invalid HMAC Signature")
            await send_response(writer, "Invalid HMAC signature\n")
            
        command = data.split()[0]
        if command == "LOGIN":
            print("LOGIN command received")
            if username is not None:
                print(f"User {username.capitalize()} attempted to login again")
                await send_response(writer, "Already logged in\n")
                continue
            username = await handle_login(writer, data.split()[1], data.split()[2])
        elif command == "COMPOSE":
            print("COMPOSE command received")
            if username is None:
                print("Unauthenticated user attempted to compose a message")
                await send_response(writer, "Not logged in\n")
                continue
            recipient = data.split()[1]
            encrypted_message = await reader.read(1024)
            message = cipher_suite.decrypt(encrypted_message).decode().strip()
            await handle_compose(writer, username.lower(), recipient, message)
        elif command == "READ":
            print("READ command received")
            if username is None:
                print("Unauthenticated user attempted to read messages")
                await send_response(writer, "Not logged in\n")
                continue
            await handle_read(writer, username)
        elif command == "EXIT":
            print("EXIT command received")
            await send_response(writer, "Goodbye\n")
            writer.close()
            await writer.wait_closed()
            print(f"User {username.capitalize()} exited")
            break
        elif command == "REGISTER":
            print("REGISTER command received")
            await handle_register(writer, data.split()[1], data.split()[2])
        else:
            print(f"Invalid command received from {addr}: {command}")
            await send_response(writer, "Invalid command\n")
            writer.close()
            await writer.wait_closed()


async def main():
    """
    Main function to start the server.
    """
    if len(sys.argv) != 2:
        print("Usage: python server.py <port>")
        sys.exit(1)
    
    port = int(sys.argv[1])
    
    server = await asyncio.start_server(handle_client, '', port)
    addr = server.sockets[0].getsockname()
    print(f"Server is listening on {addr}")
    
    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    asyncio.run(main())
