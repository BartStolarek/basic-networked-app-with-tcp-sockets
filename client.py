import asyncio
import socket
import sys


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
    return (await reader.readline()).decode().strip()


async def handle_login(reader, writer, username):
    """
    Handle the login process.
    :param reader: The reader object for the server connection.
    :param writer: The writer object for the server connection.
    :param username: The username entered by the user.
    :return: True if login is successful, False otherwise.
    """
    await send_message(writer, f"LOGIN {username}")
    response = await receive_message(reader)
    if response.startswith("Invalid username"):
        print("Invalid username. Please try again.")
        return False
    elif response.startswith("Already logged in"):
        print("You are already logged in.")
        return False
    else:
        print(f"Welcome, {username}! You have {response} unread messages.")
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

    logged_in = False
    while not logged_in:
        username = input("Enter your username: ")
        if ' ' in username:
            print("Invalid username. Spaces are not allowed.")
            continue
        logged_in = await handle_login(reader, writer, username)

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