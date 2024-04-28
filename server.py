import asyncio
import sys


async def load_messages(username):
    """
    Load messages for a user from a file.
    :param username: The username of the user.
    :return: A list of messages for the user.
    """
    try:
        with open(f"{username}.txt", "r") as file:
            messages = file.readlines()
        print(f"Loaded {len(messages)} messages for user {username}")
        return [msg.strip() for msg in messages]
    except FileNotFoundError:
        print(f"No messages found for user {username}")
        return []


async def save_message(recipient, sender, message):
    """
    Save a message from a sender to a recipient.
    :param recipient: The username of the recipient.
    :param sender: The username of the sender.
    :param message: The message to be saved.
    """
    with open(f"{recipient}.txt", "a") as file:
        file.write(f"{sender}|{message}\n")
    print(f"Message saved from {sender} to {recipient}")


async def send_response(writer, response):
    """
    Send a response to the client.
    :param writer: The writer object for the client connection.
    :param response: The response to be sent.
    """
    writer.write(response.encode())
    await writer.drain()


async def handle_login(writer, username):
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
    messages = await load_messages(username)
    await send_response(writer, f"{len(messages)}\n")
    print(f"User {username} logged in")
    return username


async def handle_compose(writer, username, recipient, message):
    """
    Handle the COMPOSE command.
    :param writer: The writer object for the client connection.
    :param username: The username of the sender.
    :param recipient: The username of the recipient.
    :param message: The message to be sent.
    """
    await save_message(recipient, username, message)
    await send_response(writer, "MESSAGE SENT\n")
    print(f"User {username} left a message to {recipient}")


async def handle_read(writer, username):
    """
    Handle the READ command.
    :param writer: The writer object for the client connection.
    :param username: The username of the user reading messages.
    """
    messages = await load_messages(username)
    if not messages:
        print(f"No messages found for user {username}")
        await send_response(writer, "READ ERROR\n")
    else:
        sender, message = messages[0].split("|", 1)
        print(f"User {username} is reading a message from {sender}: {message}")
        await send_response(writer, f"{sender}\n")
        await send_response(writer, f"{message}\n")
        print(f"Message sent to user {username}")
        messages = messages[1:]
        print(f"Removed message, {len(messages)} messages left for user {username}")
        with open(f"{username}.txt", "w") as file:
            file.write("\n".join(messages))
            if messages:
                file.write("\n")


async def handle_client(reader, writer):
    """
    Handle communication with a client.
    :param reader: The reader object for the client connection.
    :param writer: The writer object for the client connection.
    """
    addr = writer.get_extra_info('peername')
    print(f"New client connected: {addr}")
    username = None
    while True:
        data = await reader.readline()
        if not data:
            print(f"Client {addr} disconnected")
            break
        data = data.decode().strip()
        print(f"Received data from {addr}: {data}")
        
        command = data.split()[0]
        
        if command == "LOGIN":
            if username is not None:
                print(f"User {username} attempted to login again")
                await send_response(writer, "Already logged in\n")
                continue
            username = await handle_login(writer, data.split()[1])
        elif command == "COMPOSE":
            if username is None:
                print(f"Unauthenticated user attempted to compose a message")
                await send_response(writer, "Not logged in\n")
                continue
            recipient = data.split()[1]
            message = await reader.readline()
            message = message.decode().strip()
            await handle_compose(writer, username, recipient, message)
        elif command == "READ":
            if username is None:
                print(f"Unauthenticated user attempted to read messages")
                await send_response(writer, "Not logged in\n")
                continue
            await handle_read(writer, username)
        elif command == "EXIT":
            await send_response(writer, "Goodbye\n")
            writer.close()
            await writer.wait_closed()
            print(f"User {username} exited")
            break
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