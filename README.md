# Secure Messaging Application

This is a secure network messaging system that allows users to leave messages for other users. The application consists of a server process that stores messages and allows them to be retrieved, and a client process that interacts with the server using a secure protocol.

## Features

- User registration and authentication using password hashing and salting
- Encrypted communication between client and server using symmetric encryption (Fernet)
- Message integrity and authentication using HMAC signatures
- Users can send and receive encrypted messages with the assurance of authenticity and confidentiality
- Digital signatures using RSA key pairs for message authentication and non-repudiation

## Requirements

- Python 3.7 or higher
- `asyncio` module
- `cryptography` module

## Installation

1. Clone the repository to your local machine:
```
gh repo clone BartStolarek/secure-networked-app-with-tcp-sockets
```
2. Create a Python virtual environment:
```
python -m venv venv
```
3. Activate the virtual environment:
```
source venv/bin/activate
```
4. Install the required dependencies:
```
pip install -r requirements.txt
```
5. Make the shell scripts executable by running the following commands in the terminal:
```
chmod +x startServer.sh
chmod +x startClient.sh
```
## Usage

1. Start the server by running the `startServer.sh` script with a port number as the command-line parameter:
```
./startServer.sh <port>
```
If the server is unable to start (e.g., wrong arguments), an appropriate error message will be displayed.

2. Start the client by running the `startClient.sh` script with a host name and port number as command-line parameters:
```
./startClient.sh <hostname> <port>
```
Use `localhost` as the hostname if the server is running on the same machine. If the client is unable to connect, an appropriate error message will be displayed.

3. Follow the prompts in the client interface to register a new user account or log in with existing credentials.

4. Once logged in, you can compose messages, read messages, and exit the system using the provided commands.

## Protocol

The secure messaging protocol includes the following commands and responses:

- `REGISTER <username> <password>`: Client sends this command to register a new user account. The server verifies the uniqueness of the username and stores the hashed password.

- `LOGIN <username> <password>`: Client sends this command to log in with a username and password. The server verifies the credentials and responds with the number of unread messages.

- `COMPOSE <recipient>`: Client sends this command to compose a message to a recipient, followed by the encrypted message. The server stores the message along with the digital signature.

- `READ`: Client sends this command to read the earliest unread message. The server responds with the sender's username and the encrypted message. The message is removed from the server after being read.

- `EXIT`: Client sends this command to exit the system and disconnect from the server.

All communication between the client and server is encrypted using Fernet symmetric encryption. HMAC signatures are used to ensure the integrity and authenticity of the messages. RSA key pairs are used for digital signatures to provide message authentication and non-repudiation.

## Security Features

- Password hashing and salting: User passwords are hashed using SHA-256 along with a randomly generated salt to securely store them on the server.

- Encrypted communication: All messages exchanged between the client and server are encrypted using Fernet symmetric encryption, ensuring confidentiality.

- Message integrity and authentication: HMAC signatures are calculated for each message using a shared secret key, ensuring the integrity and authenticity of the messages.

- Digital signatures: RSA key pairs are used to sign and verify messages, providing message authentication and non-repudiation.

## Error Handling

- Invalid commands, usernames, or passwords are handled gracefully, and appropriate error messages are displayed to the user.

- The client ensures that only valid commands and input are sent to the server by performing client-side validation.

- If the server detects any invalid or tampered messages, it drops the connection and notifies the client.

## Author

Bart Stolarek