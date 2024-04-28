# Messaging Application

This is a network messaging system that allows users to leave messages for other users. The application consists of a server process that stores messages and allows them to be retrieved, and a client process that interacts with the server using a specific protocol.

## Features

- Users can log in with a username and send messages to other users.
- Users can read messages that were previously sent to them.
- The server can store at unlimited unread messages for each user.

## Requirements

- Python 3.7 or higher
- `asyncio` module

## Installation

1. Clone the repository to your local machine:

```gh repo clone BartStolarek/basic-networked-app-with-tcp-sockets```

2. Make the shell scripts executable by running the following commands in the terminal:

```
chmod +x startServer.sh
chmod +x startClient.sh
````

## Usage

1. Start the server by running the `startServer.sh` script with a port number as the command-line parameter:

```./startServer.sh <port>```

If the server is unable to start (e.g., wrong arguments), an appropriate error message will be displayed.

2. Start the client by running the `startClient.sh` script with a host name and port number as command-line parameters:

```./startClient.sh <hostname> <port>```

Use `localhost` as the hostname if the server is running on the same machine.
If the client is unable to connect, an appropriate error message will be displayed.

3. Follow the prompts in the client interface to log in, compose messages, read messages, and exit the system.

## Protocol

The application uses a specific protocol for communication between the client and server. Each command and response consists of a string of ASCII characters followed by the line feed character (ASCII code 10). All commands and responses are case sensitive.

- `LOGIN <username>`: Client sends this command to log in with a username. Usernames must not contain spaces.
- Server responds with the number of messages currently stored for the user.
- `COMPOSE <username>`: Client sends this command to compose a message to another user, followed by the user on a new line and message on a new line.
- Server responds with `MESSAGE SENT` if the message is successfully stored, or `MESSAGE FAILED` otherwise.
- `READ`: Client sends this command to read the earliest unread message.
- Server responds with the username of the sender and the message content, or `READ ERROR` if there are no unread messages.
- `EXIT`: Client sends this command to exit the system and disconnect from the server.

Any other message sent to or from the client is considered an error, and the receiving party should drop the connection.

## Error Handling

- If a `LOGIN` command is sent with a username containing a space, the server treats it as an error.
- If the client sends an invalid command, the server drops the connection.
- The client ensures that only valid commands are sent to the server by performing client-side validation.

## Implementation Details

- The server is implemented using `asyncio` for handling multiple client connections concurrently.
- Messages are stored in text files, with each user having their own file named `<username>.txt`.
- The client is implemented using `asyncio` for asynchronous communication with the server.
- The code follows the DRY (Don't Repeat Yourself) principle and includes comments for clarity and maintainability.

## Author

Bart Stolarek