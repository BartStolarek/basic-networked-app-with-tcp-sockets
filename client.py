import asyncio
import socket
import sys

async def send_message(writer, message):
    writer.write((message + '\n').encode())
    await writer.drain()

async def receive_message(reader):
    return (await reader.readline()).decode().strip()

async def main():
    if len(sys.argv) != 3:
        print("Usage: python client.py <hostname> <port>")
        sys.exit(1)

    hostname = sys.argv[1]
    port = int(sys.argv[2])

    reader, writer = await asyncio.open_connection(hostname, port)
    print("Connected to server")

    while True:
        username = input("Enter your username: ")
        if ' ' in username:
            print("Invalid username. Spaces are not allowed.")
            continue
        await send_message(writer, f"LOGIN {username}")
        response = await receive_message(reader)
        if response.startswith("Invalid username"):
            print("Invalid username. Please try again.")
            continue
        elif response.startswith("Already logged in"):
            print("You are already logged in.")
            continue
        else:
            print(f"Welcome, {username}! You have {response} unread messages.")
            break

    while True:
        command = input("Enter a command (COMPOSE, READ, or EXIT): ")
        if command == "COMPOSE":
            recipient = input("Enter the recipient username: ")
            message = input("Enter the message: ")
            await send_message(writer, f"COMPOSE {recipient}")
            await send_message(writer, message)
            response = await receive_message(reader)
            print(f"Server: {response}")
        elif command == "READ":
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
        elif command == "EXIT":
            await send_message(writer, "EXIT")
            print(await receive_message(reader))
            break
        else:
            print("Invalid command. Please try again.")

    writer.close()
    await writer.wait_closed()
    print("Disconnected from the server.")

if __name__ == '__main__':
    asyncio.run(main())