import socket
import argparse
import sys
import os
import crypto_utils as utils
from message import Message, MessageType

# Default connection parameters
DEFAULT_PORT = 8087
DEFAULT_HOST = 'localhost'


# Parse command line arguments
def parse_arguments():
    parser = argparse.ArgumentParser(description='Simple TLS Client')
    parser.add_argument('file', help='The file name to save to. Use - for stdout.')
    parser.add_argument('-p', '--port', type=int, default=DEFAULT_PORT, help='Port to connect to.')
    parser.add_argument('--host', default=DEFAULT_HOST, help='Hostname to connect to.')
    parser.add_argument('-v', '--verbose', action='store_true', help='Turn on debugging output.')
    return parser.parse_args()


# Main program
def main():
    args = parse_arguments()

    # Establish connection
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((args.host, args.port))

        # Send Hello message
        s.send(Message(MessageType.HELLO).to_bytes())

        # Receive and verify certificate
        server_cert_msg = Message.from_socket(s)
        if server_cert_msg.type != MessageType.CERTIFICATE:
            raise Exception("Expected a certificate message")
        server_nonce, server_cert = server_cert_msg.data[:32], server_cert_msg.data[32:]
        server_cert_obj = utils.load_certificate(server_cert)
        if not server_cert_obj:
            raise Exception("Invalid server certificate")

        # Send encrypted nonce
        client_nonce = os.urandom(32)
        encrypted_nonce = utils.encrypt_with_public_key(client_nonce, server_cert_obj.public_key())
        s.send(Message(MessageType.NONCE, encrypted_nonce).to_bytes())

        # Generate keys
        server_enc_key, server_mac_key, client_enc_key, client_mac_key = utils.generate_keys(client_nonce, server_nonce)

        # Receive server hash and validate
        server_hash_msg = Message.from_socket(s)
        if server_hash_msg.type != MessageType.HASH:
            raise Exception("Expected a hash message")
        expected_server_hash = utils.mac(b''.join([Message(MessageType.HELLO).to_bytes(),
                                                   server_cert_msg.to_bytes(),
                                                   Message(MessageType.NONCE, encrypted_nonce).to_bytes()]),
                                         server_mac_key)
        if server_hash_msg.data != expected_server_hash:
            raise Exception("Invalid server hash")

        # Send client hash
        client_hash = utils.mac(b''.join([Message(MessageType.HELLO).to_bytes(),
                                          server_cert_msg.to_bytes(),
                                          Message(MessageType.NONCE, encrypted_nonce).to_bytes()]),
                                client_mac_key)
        s.send(Message(MessageType.HASH, client_hash).to_bytes())

        # Receive and process data
        received_data = b''
        sequence_number = 0
        while True:
            data_msg = Message.from_socket(s)
            if data_msg is None:
                raise Exception("No data received from server, or connection closed unexpectedly")

            if data_msg.type != MessageType.DATA:
                break  # Assuming the non-data message signifies the end of data transmission

            decrypted_data = utils.decrypt(data_msg.data, server_enc_key)
            seq_num, data_chunk, received_mac = decrypted_data[:4], decrypted_data[4:-32], decrypted_data[-32:]
            if int.from_bytes(seq_num, "big") != sequence_number:
                raise Exception("Invalid sequence number")
            calculated_mac = utils.mac(data_chunk, server_mac_key)
            if calculated_mac != received_mac:
                raise Exception("Invalid MAC")
            received_data += data_chunk
            sequence_number += 1

        # Save or output data
        if args.file == '-':
            sys.stdout.buffer.write(received_data)
        else:
            with open(args.file, 'wb') as file:
                file.write(received_data)


if __name__ == "__main__":
    main()
