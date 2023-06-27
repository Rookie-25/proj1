const SHA256 = require('sha256');
const EC = require('elliptic').ec;
const ec = new EC('secp256k1');

class Block {
    constructor(index, timestamp, data, previousHash = '') {
        this.index = index;
        this.timestamp = timestamp;
        this.data = data;
        this.previousHash = previousHash;
        this.hash = this.calculateHash();
        this.nonce = 0;
    }//here we defined the structure of the class Block using constructor
    
    
    //we use here sha256 hashing algorithm to compute hash of  a given Block
    calculateHash(){
        return SHA256(this.index +this.previousHash +this.timestamp +JSON.stringify(this.data) +this.nonce).toString();
    }

    //using ProofOfWork consensos algorithm to mine a block in this blockchain
    proofOfWork(difficulty) {
        while (this.hash.substring(0, difficulty) !== Array(difficulty + 1).join('0')) {
            this.nonce++;
            this.hash = this.calculateHash();
        }
    }
}

//defining class Blockchain 
class Blockchain {
    constructor() {
        this.chain = [this.GenesisBlock()];
        this.difficulty = 4;
        this.newTransaction = [];
        this.miningReward = 5;
    }

    //creting the genesis Block of the Blockchain
    GenesisBlock() {
        return new Block(0, Date.now(), 'Genesis Block', '0');
    }

    getLatestBlock() {
        return this.chain[this.chain.length - 1];
    }

    //this function basically involves mining the block and rewarding the miner with 
    //the mining_reward set in the blockchain 
    //it records the reward transactions as well 
    //and passes it to the pendingtransactions array
    //this array basically records all the transactions being done until 
    //a block is mined where all of this transaction is passed as a Block Data
    New_Transactions(miningRewardAddress) {
        const rewardTransaction = new Transaction(null, miningRewardAddress, this.miningReward);
        //since rewardTransaction is basically the Blockchain awarding the miner a set amount 
        //so the from-adress of rewardTransaction is set to null 
        this.newTransaction.push(rewardTransaction);
        //creating new block to be added to blockchain
        const block = new Block(this.chain.length,Date.now(),this.newTransaction,this.getLatestBlock().hash);
        block.mineBlock(this.difficulty);

        console.log('Block successfully mined!');
        this.chain.push(block);

        this.newTransaction = [];
    }

    //creating a method to add a new transaction the newTransactions array by checking if the transaction is valid or not
    addTransaction(transaction) {
        if (!transaction.isValid()) {
            console.log('Invalid transaction. Discarding...');
            return;
        }

        this.newTransaction.push(transaction);
        console.log('Transaction added to pending transactions.');
    }

    getBalance(address) 
    {
        let balance = 0;
        for (const block of this.chain) 
        {
            for (const transaction of block.data) 
            {
                if (transaction.fromAddress === address) 
                {
                    balance -= transaction.amount;
                }
                if (transaction.toAddress === address) 
                {
                    balance += transaction.amount;
                }
            }
        }
        return balance;
    }

    //checks if the chain is Valid or not by checking if each of the previousHash of each Block is 
    //equal to the previousBlock's Hash
    Valid_chain() {
        for (let i = 1; i < this.chain.length; i++) {
            const currentBlock = this.chain[i];
            const previousBlock = this.chain[i - 1];

            if (currentBlock.hash !== currentBlock.calculateHash()) {
                return false;
            }

            if (currentBlock.previousHash !== previousBlock.hash) {
                return false;
            }
        }
        return true;
    }
}
//now defining the Transaction class its structure and its methods implemented
class Transaction {
    constructor(fromAddress, toAddress, amount) {
        this.fromAddress = fromAddress;
        this.toAddress = toAddress;
        this.amount = amount;
        this.timestamp = Date.now();
    }

    calculateHash() {
        return SHA256(this.fromAddress +this.toAddress +this.amount +this.timestamp).toString();
    }

    //we now create a method to digitally sign a transaction using secret-public key pair
    //we pass as parameter the signing key(private key)
    sign(signingKey) {
        if (signingKey.publicKey !== this.fromAddress) {
            throw new Error('You cannot sign transactions for other wallets!');
        }

        const hash = this.calculateHash();
        const signature = signingKey.sign(hash, 'base64');
        this.signature = signature.toDER('hex');
    }

    //checks if the transactioin has been properly signed or not
    //and can be verified by the public key
    isValid() {
        if (this.fromAddress === null) {
            return true;
        }

        if (!this.signature || this.signature.length === 0) {
            throw new Error('No signature found for this transaction!');
        }

        const publicKey = ec.keyFromPublic(this.fromAddress, 'hex');
        return publicKey.verify(this.calculateHash(), this.signature);
    }
}