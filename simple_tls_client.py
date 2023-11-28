import secrets
import socket
import argparse
import sys
import crypto_utils as utils
from message import Message, MessageType
import logging

# Global client socket
client = None


def connect(host, port):
    """
    Establishes a connection to the server.

    :param host: Hostname of the server.
    :param port: Port number to connect to.

    :raise exception: If connection fails.
    """
    global client
    try:
        # Initialize client socket and connect to the server
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((host, port))
        logging.info("Connection established with server.")
    except Exception as e:
        logging.error(f"Connection error: {e}")
        sys.exit(1)


def send_hello():
    """
    Sends a HELLO message to the server and receives a response.

    :return: The response data containing nonce and certificate from the server in bytes.

    :raise exception: If sending or receiving the HELLO message fails.
    """
    try:
        # Send HELLO message to server
        hello_mes = Message(MessageType.HELLO).to_bytes()
        client.sendall(hello_mes)
        logging.info("HELLO message sent.")
        response = Message.from_socket(client).data
        logging.info("Received nonce and certificate from server.")
        return response
    except Exception as e:
        logging.error(f"HELLO message error: {e}")
        sys.exit(1)


def send_encrypted_nonce(client_nonce, server_cert_obj):
    """
    Encrypts the client nonce with the server's public key and sends it to the server.

    :param client_nonce: The client-generated nonce. (bytes)
    :param server_cert_obj: The server certificate object. (X509)

    :return: The encrypted nonce in bytes.

    :raise exception: If sending the encrypted nonce fails.
    """
    try:
        # Encrypt and send client nonce
        encrypted_nonce = utils.encrypt_with_public_key(
            client_nonce, server_cert_obj.public_key()
        )
        client.sendall(Message(MessageType.NONCE, encrypted_nonce).to_bytes())
        logging.info("Encrypted nonce sent.")
        return encrypted_nonce
    except Exception as e:
        logging.error(f"Encrypted nonce error: {e}")
        sys.exit(1)


def receive_server_hash():
    """
    Receives the server hash message.

    :return: The server hash message.

    :raise exception: If receiving the server hash message fails.
    """
    try:
        # Receive server hash message
        server_hash_msg = Message.from_socket(client)
        return server_hash_msg
    except Exception as e:
        logging.error(f"Server hash reception error: {e}")
        sys.exit(1)


def verify_server_hash(server_hash_msg, expected_server_hash):
    """
    Verifies the server hash against the expected hash.

    :param server_hash_msg: The received server hash message.
    :param expected_server_hash: The expected server hash.

    :raise exception: If the server hash verification fails.
    """
    # Verify the server hash
    if server_hash_msg.data != expected_server_hash:
        logging.error("Server hash verification failed.")
        sys.exit(1)


def send_client_hash(client_hash):
    """
    Sends the client hash to the server.

    :param client_hash: The client-generated hash. (bytes)

    :raise exception: If sending the client hash fails.
    """
    try:
        # Send client hash to server
        client.sendall(Message(MessageType.HASH, client_hash).to_bytes())
        logging.info("Client hash sent.")
    except Exception as e:
        logging.error(f"Client hash sending error: {e}")
        sys.exit(1)


def receive_and_process_data(server_enc_key, server_mac_key):
    """
    Receives and processes encrypted data messages from the server.

    :param server_enc_key: The server encryption key. (bytes)
    :param server_mac_key: The server MAC key. (bytes)

    :return: The aggregated received data after decryption and MAC verification in bytes.

    :raise exception: If there's an error in data reception or processing.
    """

    received_data = b""
    sequence_number = 0
    while True:
        try:
            # Receive and process encrypted data messages
            data_msg = Message.from_socket(client)
            if not data_msg or data_msg.type != MessageType.DATA:
                break

            decrypted_data = utils.decrypt(data_msg.data, server_enc_key)
            seq_num, data_chunk, received_mac = (
                decrypted_data[:4],
                decrypted_data[4:-32],
                decrypted_data[-32:],
            )
            if int.from_bytes(seq_num, "big") != sequence_number:
                logging.error("Sequence number mismatch.")
                sys.exit(1)

            calculated_mac = utils.mac(data_chunk, server_mac_key)
            if calculated_mac != received_mac:
                logging.error("MAC verification failed.")
                sys.exit(1)

            received_data += data_chunk
            sequence_number += 1
        except Exception as e:
            logging.error(f"Data reception error: {e}")
            sys.exit(1)
    return received_data


def save_or_output_data(received_data, filename):
    """
    Saves the received data to a file or outputs to the console.

    :param received_data: The data received from the server. (bytes)
    :param filename: The filename to save the data to; use '-' for stdout.
    """

    # Save received data to file or output to console
    if filename == "-":
        sys.stdout.buffer.write(received_data)
    else:
        with open(filename, "wb") as file:
            file.write(received_data)
    logging.info("Received data processed successfully.")


def main(host, port, filename, verbose):
    """
    Main function to run the client program.

    :param host: The server hostname. (str)
    :param port: The server port number. (int)
    :param filename: The filename to save data or '-' for stdout. (str)
    :param verbose: Enable verbose logging if True. (bool)
    """

    if verbose:
        logging.basicConfig(level=logging.INFO)

    connect(host, port)
    response = send_hello()

    # Extract nonce and certificate from response
    server_nonce = response[:32]
    server_cert = response[32:]
    server_cert_obj = utils.load_certificate(server_cert)

    client_nonce = secrets.token_bytes(32)
    encrypted_nonce = send_encrypted_nonce(client_nonce, server_cert_obj)

    # Key generation
    (
        server_enc_key,
        server_mac_key,
        client_enc_key,
        client_mac_key,
    ) = utils.generate_keys(client_nonce, server_nonce)

    server_hash_msg = receive_server_hash()

    # Prepare data for hash verification
    client_hello_message = Message(MessageType.HELLO).to_bytes()
    server_certificate_message = Message(MessageType.CERTIFICATE, response).to_bytes()
    client_nonce_message = Message(MessageType.NONCE, encrypted_nonce).to_bytes()
    cumulated_data = (
        client_hello_message + server_certificate_message + client_nonce_message
    )

    # Verify server hash
    expected_server_hash = utils.mac(cumulated_data, server_mac_key)
    verify_server_hash(server_hash_msg, expected_server_hash)

    # Generate and send client hash
    client_hash = utils.mac(
        b"".join(
            [client_hello_message, server_certificate_message, client_nonce_message]
        ),
        client_mac_key,
    )
    send_client_hash(client_hash)

    # Data reception and processing
    received_data = receive_and_process_data(server_enc_key, server_mac_key)
    save_or_output_data(received_data, filename)


def parse_arguments():
    """
    Parses command-line arguments.

    :return argparse.Namespace: Parsed command-line arguments.
    """

    # Argument parsing for CLI interaction
    parser = argparse.ArgumentParser(description="Simple TLS Client")
    parser.add_argument("file", help='File name to save data, or "-" for stdout.')
    parser.add_argument(
        "-p", "--port", type=int, default=8087, help="Port to connect to."
    )
    parser.add_argument("--host", default="localhost", help="Hostname of the server.")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging."
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_arguments()
    main(args.host, args.port, args.file, args.verbose)
