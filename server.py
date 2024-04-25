import asyncio
import sys


async def load_messages(username):
    print(f"Loading messages for user {username}")
    try:
        with open(f"{username}.txt", "r") as file:
            messages = file.readlines()
        print(f"Loaded {len(messages)} messages for user {username}")
        return [msg.strip() for msg in messages]
    except FileNotFoundError:
        print(f"No messages found for user {username}")
        return []


async def save_message(recipient, sender, message):
    print(f"Saving message from {sender} to {recipient}")
    with open(f"{recipient}.txt", "a") as file:
        file.write(f"{sender}|{message}\n")
    print(f"Message saved for {recipient}")


async def handle_client(reader, writer):
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
                writer.write("Already logged in\n".encode())
                await writer.drain()
                continue
            username = data.split()[1]
            if ' ' in username:
                print(f"Invalid username: {username}")
                writer.write("Invalid username\n".encode())
                await writer.drain()
                continue
            messages = await load_messages(username)
            writer.write(f"{len(messages)}\n".encode())
            await writer.drain()
            print(f"User {username} logged in")
        elif command == "COMPOSE":
            if username is None:
                print(f"Unauthenticated user attempted to compose a message")
                writer.write("Not logged in\n".encode())
                await writer.drain()
                continue
            recipient = data.split()[1]
            message = await reader.readline()
            message = message.decode().strip()
            await save_message(recipient, username, message)
            writer.write("MESSAGE SENT\n".encode())
            await writer.drain()
            print(f"User {username} sent a message to {recipient}")
        elif command == "READ":
            if username is None:
                print(f"Unauthenticated user attempted to read messages")
                writer.write("Not logged in\n".encode())
                await writer.drain()
                continue
            messages = await load_messages(username)
            if not messages:
                print(f"No messages found for user {username}")
                writer.write("READ ERROR\n".encode())
                await writer.drain()
            else:
                sender, message = messages[0].split("|", 1)
                print(f"User {username} is reading a message from {sender}: {message}")
                writer.write(f"{sender}\n".encode())
                await writer.drain()
                writer.write(f"{message}\n".encode())
                await writer.drain()
                print(f"Message sent to user {username}")
                messages = messages[1:]
                print(f"Removed message, {len(messages)} messages left for user {username}")
                with open(f"{username}.txt", "w") as file:
                    file.write("\n".join(messages))
                    if messages:
                        file.write("\n")
        elif command == "EXIT":
            writer.write("Goodbye\n".encode())
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            print(f"User {username} exited")
            break
        else:
            print(f"Invalid command received from {addr}: {command}")
            writer.write("Invalid command\n".encode())
            await writer.drain()
            writer.close()
            await writer.wait_closed()

async def main():
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