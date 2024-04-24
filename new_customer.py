import rsa
import hashlib
import pickle
import socket
import sys
import threading
import time
import os

class Transaction:
    def __init__(self, sender, receiver, amounts, fee, message):
        self.sender = sender
        self.receiver = receiver
        self.amounts = amounts
        self.fee = fee
        self.message = message

def initialize_transaction(sender, receiver, amount, fee, message):
    # No need to check balance
    new_transaction = Transaction(sender, receiver, amount, fee, message)
    return new_transaction

def transaction_to_string(transaction):
    transaction_dict = {
        'sender': str(transaction.sender),
        'receiver': str(transaction.receiver),
        'amounts': transaction.amounts,
        'fee': transaction.fee,
        'message': transaction.message
    }
    return str(transaction_dict)

def sign_transaction(transaction, private):
    private_key = '-----BEGIN RSA PRIVATE KEY-----\n'
    private_key += private
    private_key += '\n-----END RSA PRIVATE KEY-----\n'
    private_key_pkcs = rsa.PrivateKey.load_pkcs1(private_key.encode('utf-8'))
    transaction_str = transaction_to_string(transaction)
    signature = rsa.sign(transaction_str.encode('utf-8'), private_key_pkcs, 'SHA-1')
    return signature


def handle_receive():
    while True:
        try:
            response = client.recv(4096)
            parsed_response = pickle.loads(response)
            if response:
                # print(f"[*] Message from node: {parsed_response}")
                if parsed_response["reply"] == "update_address":
                    print("Successfully send the address to miner.")
                    print("Update local address table.")
                    temp_data = parsed_response["data"]
                    for i in range(len(temp_data)):
                        address_table.append(temp_data[i]) # 更新用戶列表
                        print(f"Node {i+1} : ", temp_data[i])
                elif parsed_response["reply"] == "get_balance":
                    print("Balance = ", parsed_response["data"])
                
                elif parsed_response["reply"] == "transaction":
                    print(parsed_response["data"])
        except Exception:
            print("ERROR !!!")
            print(f"[*] Message from miner: {parsed_response}")
            os._exit(0)
'''
def handle_receive():
    while True:
        response = client.recv(4096)
        if response:
            print(f"[*] Message from node: {response}"
'''

          
def generate_address():
    public, private = rsa.newkeys(512)
    public_key = public.save_pkcs1()
    private_key = private.save_pkcs1()
    return get_address_from_public(public_key), extract_from_private(private_key)

def get_address_from_public(public):
    address = str(public).replace('\\n','')
    address = address.replace("b'-----BEGIN RSA PUBLIC KEY-----", '')
    address = address.replace("-----END RSA PUBLIC KEY-----'", '')
    address = address.replace(' ', '')
    return address

def extract_from_private(private):
    private_key = str(private).replace('\\n','')
    private_key = private_key.replace("b'-----BEGIN RSA PRIVATE KEY-----", '')
    private_key = private_key.replace("-----END RSA PRIVATE KEY-----'", '')
    private_key = private_key.replace(' ', '')
    return private_key

if __name__ == "__main__":
    target_host = "127.0.0.1" #設為127.0.0.1
    target_port = 2024 #設為miner的Port
    local_ip = "127.0.0.1" #設為127.0.0.1
    local_port = 2023 #設一個與miner不同的Port
    address_table = []
    
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect((target_host, target_port))
        print("Successfully connect to miner")
        receive_handler = threading.Thread(target=handle_receive, args=())
        receive_handler.start()
    
        command_dict = {
            "1": "generate_address",
            "2": "get_balance",
            "3": "transaction",
            "4": "close",
            "5": "apply"
        }

        while True:
            print("Command list:")
            print("1. generate_address")
            print("2. get_balance")
            print("3. transaction")
            print("4. close the application")
            print("5. apply some test tokens")
            command = input("Command: ")
            if str(command) not in command_dict.keys():
                print("Unknown command.")
                continue
            message = {
                "request": command_dict[str(command)]
            }
            if command_dict[str(command)] == "generate_address":
                address, private_key = generate_address()
                print(f"Address: {address}")
                print(f"Private key: {private_key}")
                message = {"request":"add_address","data":address}
                client.send(pickle.dumps(message))

            elif command_dict[str(command)] == "get_balance":
                address = input("Address: ")
                message['address'] = address
                client.send(pickle.dumps(message))

            elif command_dict[str(command)] == "transaction":
                message['address'] = input("Address: ")
                private_key = input("Private_key: ")
                message['receiver'] = input("Receiver: ")
                message['amount'] = input("Amount: ")
                message['fee'] = input("Fee: ")
                message['comment'] = input("Comment: ")
                new_transaction = initialize_transaction(
                    message["address"], 
                    message["receiver"],
                    int(message["amount"]),
                    int(message["fee"]),
                    message["comment"]
                )
                signature = sign_transaction(new_transaction, private_key)
                message["signature"] = signature

                client.send(pickle.dumps(message))        
            
            elif command_dict[str(command)] == "apply":
                addr = input("Address: ")
                amount = int(input("How many tokens you are going to apply : "))
                message['data'] = [addr, amount]
                client.send(pickle.dumps(message))
            
            
            elif command_dict[str(command)] == "close":
                client.send(pickle.dumps(message))
                # client.close()
                # print("!!!!")
                time.sleep(1) # 等待子執行緒關閉
                os._exit(0)
            
            
            else:
                print("Unknown command.")
            time.sleep(1)
    except:
        print("The server has not yet beeen opened. Please try connecting again later")