# client.py
import asyncio
import socket
import sys
import re

async def send_message(writer, message):
    """
    Send a message to the server.
    :param writer: The writer object for the server connection.
    :param message: The message to be sent.
    """
    writer.write((message + '\n').encode())
    await writer.drain()


async def receive_message(reader):
    """
    Receive a message from the server.
    :param reader: The reader object for the server connection.
    :return: The received message.
    """
    response = (await reader.readline()).decode().strip()
    if 'Invalid command' in response:
        print("Server error: Invalid command")
    return response


async def handle_login(reader, writer, username, password):
    """
    Handle the login process.
    :param reader: The reader object for the server connection.
    :param writer: The writer object for the server connection.
    :param username: The username entered by the user.
    :return: True if login is successful, False otherwise.
    """
    await send_message(writer, f"LOGIN {username} <{password}>")
    response = await receive_message(reader)
    if response.startswith("Invalid username"):
        print("Invalid username. Please try again.")
        return False
    elif response.startswith("Invalid password"):
        print("Invalid password. Please try again.")
        return False
    elif response.startswith("Already logged in"):
        print("You are already logged in.")
        return False
    else:
        print(f"Welcome, {username}! You have {response} unread messages.")
        return True


async def handle_register(reader, writer, username, password):
    await send_message(writer, f"REGISTER {username} <{password}>")
    response = await receive_message(reader)
    if response.startswith("Username already exists"):
        print("Username already exists. Please try again.")
        return False
    elif response.startswith("Invalid password"):
        print("Invalid password. Please try again.")
        return False
    elif response.startswith("Invalid"):
        return False
    else:
        print(f"Thank you for registering, please log in with your credentials.")
        return True

async def handle_compose(reader, writer):
    """
    Handle the compose message process.
    :param reader: The reader object for the server connection.
    :param writer: The writer object for the server connection.
    """
    recipient = input("Enter the recipient username: ")
    message = input("Enter the message: ")
    await send_message(writer, f"COMPOSE {recipient}")
    await send_message(writer, message)
    response = await receive_message(reader)
    print(f"Server: {response}")


async def handle_read(reader, writer):
    """
    Handle the read message process.
    :param reader: The reader object for the server connection.
    :param writer: The writer object for the server connection.
    """
    await send_message(writer, "READ")
    response = await receive_message(reader)
    if response == "READ ERROR":
        print("No unread messages")
    elif response == "Not logged in":
        print("You are not logged in.")
    else:
        sender = response
        message = await receive_message(reader)
        print(f"From: {sender}")
        print(f"Message: {message}")


async def handle_exit(reader, writer):
    """
    Handle the exit process.
    :param reader: The reader object for the server connection.
    :param writer: The writer object for the server connection.
    """
    await send_message(writer, "EXIT")
    print(await receive_message(reader))

def validate_password(password):
    """
    Validate the password.
    :param password: The password to be validated.
    :return: The password if it is valid, None otherwise.
    """
    if len(password) < 8:
        print("Invalid password. Password must be at least 8 characters.")
        return None
    
    if ' ' in password:
        print("Invalid password. Password must not contain spaces.")
        return None
    
    if not re.search(r'[A-Z]', password):
        print("Invalid password. Password must contain at least one uppercase letter.")
        return None
    
    if not re.search(r'[a-z]', password):
        print("Invalid password. Password must contain at least one lowercase letter.")
        return None
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        print("Invalid password. Password must contain at least one special character.")
        return None
    
    return password


def obtain_credentials():
    """
    Obtain the username and password from the user.
    :return: The username and password entered by the user.
    """
    obtained = False
    while not obtained:
        username = input("Enter a username: ")
        if ' ' in username:
            print("Invalid username. Spaces are not allowed.")
            continue
        
        password = input("Enter a password: ")
        if validate_password(password):
            obtained = True
            continue
    return username, password


async def main():
    """
    Main function to run the client.
    """
    if len(sys.argv) != 3:
        print("Usage: python client.py <hostname> <port>")
        sys.exit(1)

    hostname = sys.argv[1]
    port = int(sys.argv[2])

    reader, writer = await asyncio.open_connection(hostname, port)
    print("Connected to server")

    registered = False
    while not registered:
        register = input("Are you a registered user? (Y/N): ")
        if isinstance(register, str) and register.lower() == "y":
            registered = True
            continue
        elif isinstance(register, str) and register.lower() == "n":
            username, password = obtain_credentials()
            registered = await handle_register(reader, writer, username, password)
            continue
        else:
            print("Invalid input. Please try again.")
        
    logged_in = False
    while not logged_in:
        username, password = obtain_credentials()
        logged_in = await handle_login(reader, writer, username, password)

    while True:
        command = input("Enter a command (COMPOSE, READ, or EXIT): ")
        if command == "COMPOSE":
            await handle_compose(reader, writer)
        elif command == "READ":
            await handle_read(reader, writer)
        elif command == "EXIT":
            await handle_exit(reader, writer)
            break
        else:
            print("Invalid command. Please try again.")

    writer.close()
    await writer.wait_closed()
    print("Disconnected from the server.")


if __name__ == '__main__':
    asyncio.run(main())