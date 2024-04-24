import rsa
import hashlib
import time
import socket
import threading
import sys
import pickle
import os
import pandas as pd

class Transaction:
    def __init__(self, sender, receiver, amounts, fee, message):
        self.sender = sender
        self.receiver = receiver
        self.amounts = amounts
        self.fee = fee
        self.message = message
        
class Block:
    def __init__(self, previous_hash, difficulty, miner, miner_rewards):
        self.previous_hash = previous_hash
        self.hash = ''
        self.difficulty = difficulty
        self.nonce = 0
        self.timestamp = int(time.time())
        self.transactions = []
        self.miner = miner
        self.miner_rewards = miner_rewards

class BlockChain:
    def __init__(self):
        self.adjust_difficulty_blocks = 10
        self.difficulty = 5
        self.block_time = 30
        self.mining_rewards = 10
        self.block_limitation = 32
        self.chain = []
        self.pending_transactions = []
        # For P2P connection
        self.socket_host = "127.0.0.1" # 設為127.0.0.1
        self.socket_port = 2024
        self.start_socket_server()
        # maintain the p2p network
        self.address_table = [] # [addr, apply tokens]
        # temp
        self.mining_flag = 1
        # file name for the final output !
        self.ChainFileName='blockchain.csv'
        
    def transaction_to_string(self, transaction):
        transaction_dict = {
            'sender': str(transaction.sender),
            'receiver': str(transaction.receiver),
            'amounts': transaction.amounts,
            'fee': transaction.fee,
            'message': transaction.message
        }
        return str(transaction_dict)

    def get_transactions_string(self, block):
        transaction_str = ''
        for transaction in block.transactions:
            transaction_str += self.transaction_to_string(transaction)
        return transaction_str

    def get_hash(self, block, nonce):
        s = hashlib.sha1()
        s.update(
            (
                block.previous_hash
                + str(block.timestamp)
                + self.get_transactions_string(block)
                + str(nonce)
            ).encode("utf-8")
        )
        h = s.hexdigest()
        return h

    def create_genesis_block(self):
        print("Create genesis block...")
        new_block = Block('Hello World!', self.difficulty, 'lkm543', self.mining_rewards)
        new_block.hash = self.get_hash(new_block, 0)
        self.chain.append(new_block)

    def add_transaction_to_block(self, block):
        # Get the transaction with highest fee by block_limitation
        self.pending_transactions.sort(key=lambda x: x.fee, reverse=True)
        if len(self.pending_transactions) > self.block_limitation:
            transcation_accepted = self.pending_transactions[:self.block_limitation]
            self.pending_transactions = self.pending_transactions[self.block_limitation:]
        else:
            transcation_accepted = self.pending_transactions
            self.pending_transactions = []
        block.transactions = transcation_accepted
        
    def mine_block(self, miner):
        start = time.process_time()

        last_block = self.chain[-1]
        new_block = Block(last_block.hash, self.difficulty, miner, self.mining_rewards)

        self.add_transaction_to_block(new_block)
        new_block.previous_hash = last_block.hash
        new_block.difficulty = self.difficulty
        new_block.hash = self.get_hash(new_block, new_block.nonce)

        while new_block.hash[0: self.difficulty] != '0' * self.difficulty:
            new_block.nonce += 1
            new_block.hash = self.get_hash(new_block, new_block.nonce)

        time_consumed = round(time.process_time() - start, 5)
        print(f"Hash found: {new_block.hash} @ difficulty {self.difficulty}, time cost: {time_consumed}s")
        self.chain.append(new_block)
        
    def adjust_difficulty(self):
        if len(self.chain) % self.adjust_difficulty_blocks != 0:
            return self.difficulty
        elif len(self.chain) <= self.adjust_difficulty_blocks:
            return self.difficulty
        else:
            start = self.chain[-1*self.adjust_difficulty_blocks-1].timestamp
            finish = self.chain[-1].timestamp
            average_time_consumed = round((finish - start) / (self.adjust_difficulty_blocks), 2)
            if average_time_consumed > self.block_time:
                print(f"Average block time:{average_time_consumed}s. Lower the difficulty")
                self.difficulty -= 1
            else:
                print(f"Average block time:{average_time_consumed}s. High up the difficulty")
                self.difficulty += 1
    
    def get_balance(self, account):
        balance = 0
        for block in self.chain:
            # Check miner reward
            miner = False
            if block.miner == account:
                miner = True
                balance += block.miner_rewards
            for transaction in block.transactions:
                if miner:
                    balance += transaction.fee
                if transaction.sender == account:
                    balance -= transaction.amounts
                    balance -= transaction.fee
                elif transaction.receiver == account:
                    balance += transaction.amounts
        for i in self.address_table:
            if account == i[0]:
                balance += i[1]
                break

        return balance

    def verify_blockchain(self):
        previous_hash = ''
        for idx,block in enumerate(self.chain):
            if self.get_hash(block, block.nonce) != block.hash:
                print("Error:Hash not matched!")
                return False
            elif previous_hash != block.previous_hash and idx:
                print("Error:Hash not matched to previous_hash")
                return False
            previous_hash = block.hash
        print("Hash correct!")
        return True

    def generate_address(self):
        public, private = rsa.newkeys(512)
        public_key = public.save_pkcs1()
        private_key = private.save_pkcs1()
        
        return self.get_address_from_public(public_key), private_key
    
    def get_address_from_public(self, public):
        address = str(public).replace('\\n','')
        address = address.replace("b'-----BEGIN RSA PUBLIC KEY-----", '')
        address = address.replace("-----END RSA PUBLIC KEY-----'", '')
        address = address.replace(' ', '')
        print('Address:', address)
        self.address_table.append([address, 0]) # 將 miner 的 address 存入 table
        return address
    
    def initialize_transaction(self, sender, receiver, amount, fee, message):
        if self.get_balance(sender) < amount + fee:
            print("Balance not enough!")
            return "Balance not enough!"
        new_transaction = Transaction(sender, receiver, amount, fee, message)
        return new_transaction

    def sign_transaction(self, transaction, private_key):
        private_key_pkcs = rsa.PrivateKey.load_pkcs1(private_key)
        transaction_str = self.transaction_to_string(transaction)
        signature = rsa.sign(transaction_str.encode('utf-8'), private_key_pkcs, 'SHA-1')
        return signature

    def add_transaction(self, transaction, signature):
        public_key = '-----BEGIN RSA PUBLIC KEY-----\n'
        public_key += transaction.sender
        public_key += '\n-----END RSA PUBLIC KEY-----\n'
        public_key_pkcs = rsa.PublicKey.load_pkcs1(public_key.encode('utf-8'))
        transaction_str = self.transaction_to_string(transaction)
        if transaction.fee + transaction.amounts > self.get_balance(transaction.sender):
            print("Balance not enough!")
            return "Balance not enough!"
        try:
            # 驗證發送者
            rsa.verify(transaction_str.encode('utf-8'), signature, public_key_pkcs)
            print("Transaction was verified! It may be packed into block later.")
            self.pending_transactions.append(transaction)
            return True
        except Exception:
            print("RSA Verified wrong!")
            return "RSA Verified wrong!"
        
    def start(self):
        address, private = self.generate_address()
        self.create_genesis_block()
        if True:
            t = threading.Thread(target=self.interrup_control)
            t.start()

            while(self.mining_flag == 1):            
                self.mine_block(address)
                print("balance amount: ",self.get_balance(address))
                self.adjust_difficulty()
            #if(len(self.chain)==5):
            #    break
        # print("pass start function!!!")
        
    def interrup_control(self):
        self.mining_flag = int(input("In interrup_control function : input value 0 to interrup current work on mining new block. "))
 
    def start_socket_server(self):
        t = threading.Thread(target=self.wait_for_socket_connection)
        t.start()

    def wait_for_socket_connection(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.socket_host, self.socket_port))
            s.listen()
            while True:
                conn, address = s.accept()

                client_handler = threading.Thread(
                    target=self.receive_socket_message,
                    args=(conn, address)
                )
                client_handler.start()
                
    def receive_socket_message(self, connection, address):
        with connection:
            print(f'Connected by: {address}')
            while True:
                try:
                    message = connection.recv(1024)
                    parsed_message = pickle.loads(message) # decode message -> dict{'request':..., 'date':...}
                    print("parsed_message : ", parsed_message)
                except Exception:
                    #print("Something wrong while decode the message !!!")
                    #print(parsed_message)
                    #os._exit(0)
                    pass
                
                if message:
                    if parsed_message["request"] == "get_balance":
                        print("Start to get the balance for client...")
                        address = parsed_message["address"]
                        balance = self.get_balance(address)
                        response = {
                            "reply": "get_balance",
                            "data": balance
                        }
                        connection.send(pickle.dumps(response))

                    elif parsed_message["request"] == "add_address":
                        print("Put client's address into database")
                        temp_list=[]
                        for i in self.address_table:
                            temp_list.append(i[0])    
                        self.address_table.append([parsed_message['data'], 0]) # store the address into address_table 
                        response = {
                            "reply":"update_address",
                            "data":temp_list
                        }
                        connection.send(pickle.dumps(response))

                    elif parsed_message["request"] == "transaction":
                        print("Start to transaction for client...")
                        print("The message: ")
                        print(parsed_message)
                        address = parsed_message["address"]
                        new_transaction = self.initialize_transaction(
                            parsed_message["address"], 
                            parsed_message["receiver"],
                            int(parsed_message["amount"]),
                            int(parsed_message["fee"]),
                            parsed_message["comment"]
                        )
                        
                        if type(new_transaction) == type(""):
                            result_message = "The Transaction is rejected by miner, since y balance is not enough."
                        else:
                            result_message = self.add_transaction(
                                new_transaction,
                                parsed_message["signature"]
                            )
                        
                        response = {
                            "reply": "transaction",
                            "data": result_message
                        }
                        connection.send(pickle.dumps(response))

                    elif parsed_message["request"] == "apply":
                        # data : addr, amount
                        temp_list = parsed_message["data"]
                        for i in self.address_table:
                            if temp_list[0] == i[0]:
                                i[1] += temp_list[1]
                                break
                        for i in self.address_table:
                            print(i)

                    # 接收到同步區塊的請求
                    elif parsed_message["request"] == "clone_blockchain":
                        print(f"[*] Receive blockchain clone request by {address}...")
                        message = {
                            "request": "upload_blockchain",
                            "blockchain_data": self
                        }
                        connection.sendall(pickle.dumps(message))
                        continue
                        
                    elif parsed_message['request'] == "close":
                        print(f"address '{address}' has disconnected to the miner.")
                        time.sleep(3)
                        connection.close()
                        break
                    
                    else:
                        response = {
                            "message": "Unknown command."
                        }                  

if __name__ == '__main__':
    block = BlockChain()
    block.start()
    
    print("input value 0 to stop the entire application.")
    control = int(input())
    if control==0:
        temp_list = []
        for save_block in block.chain:
            temp_list.append([save_block.previous_hash, save_block.difficulty, save_block.transactions,
                                save_block.hash, save_block.timestamp])
        df = pd.DataFrame(temp_list)
        df.to_csv( block.ChainFileName ,index= False ,header=None)
        os._exit(0)
        