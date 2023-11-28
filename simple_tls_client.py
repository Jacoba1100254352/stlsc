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
    global client
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))
    logging.info("Connected to server.")


def send_hello():
    hello_mes = Message(MessageType.HELLO).to_bytes()
    client.sendall(hello_mes)
    logging.info("Hello sent.")
    response = Message.from_socket(client).data
    logging.info("Nonce & Certificate received.")
    return response


def main(host, port, filename, verbose):
    if verbose:
        logging.basicConfig(level=logging.INFO)

    connect(host, port)
    response = send_hello()

    # Splitting nonce and certificate from the response
    server_nonce = response[:32]
    server_cert = response[32:]
    server_cert_obj = utils.load_certificate(server_cert)

    client_nonce = secrets.token_bytes(32)  # Using secrets for nonce generation
    encrypted_nonce = utils.encrypt_with_public_key(client_nonce, server_cert_obj.public_key())
    client.sendall(Message(MessageType.NONCE, encrypted_nonce).to_bytes())
    logging.info("Encrypted nonce sent.")

    server_enc_key, server_mac_key, client_enc_key, client_mac_key = utils.generate_keys(client_nonce, server_nonce)

    # Receive server hash message
    server_hash_msg = Message.from_socket(client)

    # Forming cumulative data as in the working script
    client_hello_message = Message(MessageType.HELLO).to_bytes()
    server_certificate_message = Message(MessageType.CERTIFICATE, response).to_bytes()
    client_nonce_message = Message(MessageType.NONCE, encrypted_nonce).to_bytes()
    cumulated_data = client_hello_message + server_certificate_message + client_nonce_message

    expected_server_hash = utils.mac(cumulated_data, server_mac_key)
    logging.info(f"Server Hash (Received): {server_hash_msg.data}")
    logging.info(f"Server Hash (Expected): {expected_server_hash}")

    if server_hash_msg.data != expected_server_hash:
        logging.error("Invalid server hash.")
        sys.exit(1)

    client_hash = utils.mac(b''.join([Message(MessageType.HELLO).to_bytes(), response]),
                            client_mac_key)
    client.sendall(Message(MessageType.HASH, client_hash).to_bytes())
    logging.info("Client hash sent.")

    # Receive and process data
    received_data = b''
    sequence_number = 0
    while True:
        data_msg = Message.from_socket(client)
        if not data_msg or data_msg.type != MessageType.DATA:
            break

        decrypted_data = utils.decrypt(data_msg.data, server_enc_key)
        seq_num, data_chunk, received_mac = decrypted_data[:4], decrypted_data[4:-32], decrypted_data[-32:]
        if int.from_bytes(seq_num, "big") != sequence_number:
            logging.error("Invalid sequence number.")
            sys.exit(1)
        calculated_mac = utils.mac(data_chunk, server_mac_key)
        if calculated_mac != received_mac:
            logging.error("Invalid MAC.")
            sys.exit(1)
        received_data += data_chunk
        sequence_number += 1

    # Save or output data
    if filename == '-':
        sys.stdout.buffer.write(received_data)
    else:
        with open(filename, 'wb') as file:
            file.write(received_data)
    logging.info("Data received and saved")


def parse_arguments():
    parser = argparse.ArgumentParser(description='Simple TLS Client')
    parser.add_argument('file', help='The file name to save to. Use - for stdout.')
    parser.add_argument('-p', '--port', type=int, default=8087, help='Port to connect to.')
    parser.add_argument('--host', default='localhost', help='Hostname to connect to.')
    parser.add_argument('-v', '--verbose', action='store_true', help='Turn on debugging output.')
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_arguments()
    main(args.host, args.port, args.file, args.verbose)
