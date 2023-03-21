import Weblgcy from 'index';
import utils from 'utils';
import * as Ethers from 'ethers';

const USDL_MESSAGE_HEADER = '\x19LGCY Signed Message:\n32';
const ETH_MESSAGE_HEADER = '\x19Ethereum Signed Message:\n32';

export default class Legacy {
    constructor(weblgcy = false) {
        if (!weblgcy || !weblgcy instanceof Weblgcy)
            throw new Error('Expected instance of Weblgcy');

        this.weblgcy = weblgcy;
        this.injectPromise = utils.promiseInjector(this);
    }

    _parseToken(token) {
        return {
            ...token,
            name: this.weblgcy.toUtf8(token.name),
            abbr: token.abbr && this.weblgcy.toUtf8(token.abbr),
            description: token.description && this.weblgcy.toUtf8(token.description),
            url: token.url && this.weblgcy.toUtf8(token.url)
        };
    }

    getCurrentBlock(callback = false) {
        if (!callback)
            return this.injectPromise(this.getCurrentBlock);

        this.weblgcy.fullNode.request('wallet/getnowblock').then(block => {
            callback(null, block);
        }).catch(err => callback(err));
    }

    getConfirmedCurrentBlock(callback = false) {
        if (!callback)
            return this.injectPromise(this.getConfirmedCurrentBlock);

        this.weblgcy.solidityNode.request('walletsolidity/getnowblock').then(block => {
            callback(null, block);
        }).catch(err => callback(err));
    }

    getBlock(block = this.weblgcy.defaultBlock, callback = false) {
        if (utils.isFunction(block)) {
            callback = block;
            block = this.weblgcy.defaultBlock;
        }

        if (!callback)
            return this.injectPromise(this.getBlock, block);

        if (block === false)
            return callback('No block identifier provided');

        if (block == 'earliest')
            block = 0;

        if (block == 'latest')
            return this.getCurrentBlock(callback);

        if (isNaN(block) && utils.isHex(block))
            return this.getBlockByHash(block, callback);

        this.getBlockByNumber(block, callback);
    }

    getBlockByHash(blockHash, callback = false) {
        if (!callback)
            return this.injectPromise(this.getBlockByHash, blockHash);

        this.weblgcy.fullNode.request('wallet/getblockbyid', {
            value: blockHash
        }, 'post').then(block => {
            if (!Object.keys(block).length)
                return callback('Block not found');

            callback(null, block);
        }).catch(err => callback(err));
    }

    getBlockByNumber(blockID, callback = false) {
        if (!callback)
            return this.injectPromise(this.getBlockByNumber, blockID);

        if (!utils.isInteger(blockID) || blockID < 0)
            return callback('Invalid block number provided');

        this.weblgcy.fullNode.request('wallet/getblockbynum', {
            num: parseInt(blockID)
        }, 'post').then(block => {
            if (!Object.keys(block).length)
                return callback('Block not found');

            callback(null, block);
        }).catch(err => callback(err));
    }

    getBlockTransactionCount(block = this.weblgcy.defaultBlock, callback = false) {
        if (utils.isFunction(block)) {
            callback = block;
            block = this.weblgcy.defaultBlock;
        }

        if (!callback)
            return this.injectPromise(this.getBlockTransactionCount, block);

        this.getBlock(block).then(({transactions = []}) => {
            callback(null, transactions.length);
        }).catch(err => callback(err));
    }

    getTransactionFromBlock(block = this.weblgcy.defaultBlock, index = 0, callback = false) {
        if (utils.isFunction(index)) {
            callback = index;
            index = 0;
        }

        if (utils.isFunction(block)) {
            callback = block;
            block = this.weblgcy.defaultBlock;
        }

        if (!callback)
            return this.injectPromise(this.getTransactionFromBlock, block, index);

        if (!utils.isInteger(index) || index < 0)
            return callback('Invalid transaction index provided');

        this.getBlock(block).then(({transactions = false}) => {
            if (!transactions || transactions.length < index)
                return callback('Transaction not found in block');

            callback(null, transactions[index]);
        }).catch(err => callback(err));
    }

    getTransaction(transactionID, callback = false) {
        if (!callback)
            return this.injectPromise(this.getTransaction, transactionID);

        this.weblgcy.fullNode.request('wallet/gettransactionbyid', {
            value: transactionID
        }, 'post').then(transaction => {
            if (!Object.keys(transaction).length)
                return callback('Transaction not found in gettransaction');

            callback(null, transaction);
        }).catch(err => callback(err));
    }

    getConfirmedTransaction(transactionID, callback = false) {
        if (!callback)
            return this.injectPromise(this.getConfirmedTransaction, transactionID);

        this.weblgcy.solidityNode.request('walletsolidity/gettransactionbyid', {
            value: transactionID
        }, 'post').then(transaction => {
            if (!Object.keys(transaction).length)
                return callback('Transaction not found in confirmation');

            callback(null, transaction);
        }).catch(err => callback(err));
    }

    getTransactionInfo(transactionID, callback = false) {
        if (!callback)
            return this.injectPromise(this.getTransactionInfo, transactionID);

        this.weblgcy.solidityNode.request('walletsolidity/gettransactioninfobyid', {
            value: transactionID
        }, 'post').then(transaction => {
            callback(null, transaction);
        }).catch(err => callback(err));
    }

    getTransactionsToAddress(address = this.weblgcy.defaultAddress.hex, limit = 30, offset = 0, callback = false) {
        if (utils.isFunction(offset)) {
            callback = offset;
            offset = 0;
        }

        if (utils.isFunction(limit)) {
            callback = limit;
            limit = 30;
        }

        if (!callback)
            return this.injectPromise(this.getTransactionsToAddress, address, limit, offset);

        address = this.weblgcy.address.toHex(address);

        return this.getTransactionsRelated(address, 'to', limit, offset, callback);
    }

    getTransactionsFromAddress(address = this.weblgcy.defaultAddress.hex, limit = 30, offset = 0, callback = false) {
        if (utils.isFunction(offset)) {
            callback = offset;
            offset = 0;
        }

        if (utils.isFunction(limit)) {
            callback = limit;
            limit = 30;
        }

        if (!callback)
            return this.injectPromise(this.getTransactionsFromAddress, address, limit, offset);

        address = this.weblgcy.address.toHex(address);

        return this.getTransactionsRelated(address, 'from', limit, offset, callback);
    }

    async getTransactionsRelated(address = this.weblgcy.defaultAddress.hex, direction = 'all', limit = 30, offset = 0, callback = false) {
        if (utils.isFunction(offset)) {
            callback = offset;
            offset = 0;
        }

        if (utils.isFunction(limit)) {
            callback = limit;
            limit = 30;
        }

        if (utils.isFunction(direction)) {
            callback = direction;
            direction = 'all';
        }

        if (utils.isFunction(address)) {
            callback = address;
            address = this.weblgcy.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.getTransactionsRelated, address, direction, limit, offset);

        if (!['to', 'from', 'all'].includes(direction))
            return callback('Invalid direction provided: Expected "to", "from" or "all"');

        if (direction == 'all') {
            try {
                const [from, to] = await Promise.all([
                    this.getTransactionsRelated(address, 'from', limit, offset),
                    this.getTransactionsRelated(address, 'to', limit, offset)
                ])

                return callback(null, [
                    ...from.map(tx => (tx.direction = 'from', tx)),
                    ...to.map(tx => (tx.direction = 'to', tx))
                ].sort((a, b) => {
                    return b.raw_data.timestamp - a.raw_data.timestamp
                }));
            } catch (ex) {
                return callback(ex);
            }
        }

        if (!this.weblgcy.isAddress(address))
            return callback('Invalid address provided');

        if (!utils.isInteger(limit) || limit < 0 || (offset && limit < 1))
            return callback('Invalid limit provided');

        if (!utils.isInteger(offset) || offset < 0)
            return callback('Invalid offset provided');

        address = this.weblgcy.address.toHex(address);

        this.weblgcy.solidityNode.request(`walletextension/gettransactions${direction}this`, {
            account: {
                address
            },
            offset,
            limit
        }, 'post').then(({transaction}) => {
            callback(null, transaction);
        }).catch(err => callback(err));
    }

    getAccount(address = this.weblgcy.defaultAddress.hex, callback = false) {
        if (utils.isFunction(address)) {
            callback = address;
            address = this.weblgcy.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.getAccount, address);

        if (!this.weblgcy.isAddress(address))
            return callback('Invalid address provided');

        address = this.weblgcy.address.toHex(address);

        this.weblgcy.solidityNode.request('walletsolidity/getaccount', {
            address
        }, 'post').then(account => {
            callback(null, account);
        }).catch(err => callback(err));
    }

    getBalance(address = this.weblgcy.defaultAddress.hex, callback = false) {
        if (utils.isFunction(address)) {
            callback = address;
            address = this.weblgcy.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.getBalance, address);

        this.getAccount(address).then(({balance = 0}) => {
            callback(null, balance);
        }).catch(err => callback(err));
    }

    getUnconfirmedAccount(address = this.weblgcy.defaultAddress.hex, callback = false) {
        if (utils.isFunction(address)) {
            callback = address;
            address = this.weblgcy.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.getUnconfirmedAccount, address);

        if (!this.weblgcy.isAddress(address))
            return callback('Invalid address provided');

        address = this.weblgcy.address.toHex(address);

        this.weblgcy.fullNode.request('wallet/getaccount', {
            address
        }, 'post').then(account => {
            callback(null, account);
        }).catch(err => callback(err));
    }

    getUnconfirmedBalance(address = this.weblgcy.defaultAddress.hex, callback = false) {
        if (utils.isFunction(address)) {
            callback = address;
            address = this.weblgcy.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.getUnconfirmedBalance, address);

        this.getUnconfirmedAccount(address).then(({balance = 0}) => {
            callback(null, balance);
        }).catch(err => callback(err));
    }

    getBandwidth(address = this.weblgcy.defaultAddress.hex, callback = false) {
        if (utils.isFunction(address)) {
            callback = address;
            address = this.weblgcy.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.getBandwidth, address);

        if (!this.weblgcy.isAddress(address))
            return callback('Invalid address provided');

        address = this.weblgcy.address.toHex(address);

        this.weblgcy.fullNode.request('wallet/getaccountnet', {
            address
        }, 'post').then(({freeNetUsed = 0, freeNetLimit = 0, NetUsed = 0, NetLimit = 0}) => {
            callback(null, (freeNetLimit - freeNetUsed) + (NetLimit - NetUsed));
        }).catch(err => callback(err));
    }

    getTokensIssuedByAddress(address = this.weblgcy.defaultAddress.hex, callback = false) {
        if (utils.isFunction(address)) {
            callback = address;
            address = this.weblgcy.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.getTokensIssuedByAddress, address);

        if (!this.weblgcy.isAddress(address))
            return callback('Invalid address provided');

        address = this.weblgcy.address.toHex(address);

        this.weblgcy.fullNode.request('wallet/getassetissuebyaccount', {
            address
        }, 'post').then(({assetIssue = false}) => {
            if (!assetIssue)
                return callback(null, {});

            const tokens = assetIssue.map(token => {
                return this._parseToken(token);
            }).reduce((tokens, token) => {
                return tokens[token.name] = token, tokens;
            }, {});

            callback(null, tokens);
        }).catch(err => callback(err));
    }

    getTokenFromID(tokenID = false, callback = false) {
        if (!callback)
            return this.injectPromise(this.getTokenFromID, tokenID);

        if (utils.isInteger(tokenID))
            tokenID = tokenID.toString()

        if (!utils.isString(tokenID) || !tokenID.length)
            return callback('Invalid token ID provided');

        this.weblgcy.fullNode.request('wallet/getassetissuebyname', {
            value: this.weblgcy.fromUtf8(tokenID)
        }, 'post').then(token => {
            if (!token.name)
                return callback('Token does not exist');

            callback(null, this._parseToken(token));
        }).catch(err => callback(err));
    }

    listNodes(callback = false) {
        if (!callback)
            return this.injectPromise(this.listNodes);

        this.weblgcy.fullNode.request('wallet/listnodes').then(({nodes = []}) => {
            callback(null, nodes.map(({address: {host, port}}) => (
                `${this.weblgcy.toUtf8(host)}:${port}`
            )));
        }).catch(err => callback(err));
    }

    getBlockRange(start = 0, end = 30, callback = false) {
        if (utils.isFunction(end)) {
            callback = end;
            end = 30;
        }

        if (utils.isFunction(start)) {
            callback = start;
            start = 0;
        }

        if (!callback)
            return this.injectPromise(this.getBlockRange, start, end);

        if (!utils.isInteger(start) || start < 0)
            return callback('Invalid start of range provided');

        if (!utils.isInteger(end) || end <= start)
            return callback('Invalid end of range provided');

        this.weblgcy.fullNode.request('wallet/getblockbylimitnext', {
            startNum: parseInt(start),
            endNum: parseInt(end) + 1
        }, 'post').then(({block = []}) => {
            callback(null, block);
        }).catch(err => callback(err));
    }

    listSuperRepresentatives(callback = false) {
        if (!callback)
            return this.injectPromise(this.listSuperRepresentatives);

        this.weblgcy.fullNode.request('wallet/listwitnesses').then(({witnesses = []}) => {
            callback(null, witnesses);
        }).catch(err => callback(err));
    }

    listTokens(limit = 0, offset = 0, callback = false) {
        if (utils.isFunction(offset)) {
            callback = offset;
            offset = 0;
        }

        if (utils.isFunction(limit)) {
            callback = limit;
            limit = 0;
        }

        if (!callback)
            return this.injectPromise(this.listTokens, limit, offset);

        if (!utils.isInteger(limit) || limit < 0 || (offset && limit < 1))
            return callback('Invalid limit provided');

        if (!utils.isInteger(offset) || offset < 0)
            return callback('Invalid offset provided');

        if (!limit) {
            return this.weblgcy.fullNode.request('wallet/getassetissuelist').then(({assetIssue = []}) => {
                callback(null, assetIssue.map(token => this._parseToken(token)));
            }).catch(err => callback(err));
        }

        this.weblgcy.fullNode.request('wallet/getpaginatedassetissuelist', {
            offset: parseInt(offset),
            limit: parseInt(limit)
        }, 'post').then(({assetIssue = []}) => {
            callback(null, assetIssue.map(token => this._parseToken(token)));
        }).catch(err => callback(err));
    }

    timeUntilNextVoteCycle(callback = false) {
        if (!callback)
            return this.injectPromise(this.timeUntilNextVoteCycle);

        this.weblgcy.fullNode.request('wallet/getnextmaintenancetime').then(({num = -1}) => {
            if (num == -1)
                return callback('Failed to get time until next vote cycle');

            callback(null, Math.floor(num / 1000));
        }).catch(err => callback(err));
    }

    getContract(contractAddress, callback = false) {
        if (!callback)
            return this.injectPromise(this.getContract, contractAddress);

        if (!this.weblgcy.isAddress(contractAddress))
            return callback('Invalid contract address provided');

        contractAddress = this.weblgcy.address.toHex(contractAddress);

        this.weblgcy.fullNode.request('wallet/getcontract', {
            value: contractAddress
        }).then(contract => {
            if (contract.Error)
                return callback('Contract does not exist');

            callback(null, contract);
        }).catch(err => callback(err));
    }

    async verifyMessage(message = false, signature = false, address = this.weblgcy.defaultAddress.base58, useLgcyHeader = true, callback = false) {
        if (utils.isFunction(address)) {
            callback = address;
            address = this.weblgcy.defaultAddress.base58;
            useLgcyHeader = true;
        }

        if (utils.isFunction(useLgcyHeader)) {
            callback = useLgcyHeader;
            useLgcyHeader = true;
        }

        if (!callback)
            return this.injectPromise(this.verifyMessage, message, signature, address, useLgcyHeader);

        if (!utils.isHex(message))
            return callback('Expected hex message input');

        if (message.substr(0, 2) == '0x')
            message = message.substring(2);

        if (signature.substr(0, 2) == '0x')
            signature = signature.substr(2);

        const messageBytes = [
            ...Ethers.utils.toUtf8Bytes(useLgcyHeader ? USDL_MESSAGE_HEADER : ETH_MESSAGE_HEADER),
            ...utils.code.hexStr2byteArray(message)
        ];

        const messageDigest = Ethers.utils.keccak256(messageBytes);
        const recovered = Ethers.utils.recoverAddress(messageDigest, {
            recoveryParam: signature.substring(128, 130) == '1c' ? 1 : 0,
            r: '0x' + signature.substring(0, 64),
            s: '0x' + signature.substring(64, 128)
        });

        const lgcyAddress = '30' + recovered.substr(2);
        const base58Address = this.weblgcy.address.fromHex(lgcyAddress);

        if (base58Address == this.weblgcy.address.fromHex(address))
            return callback(null, true);

        callback('Signature does not match');
    }

    async sign(transaction = false, privateKey = this.weblgcy.defaultPrivateKey, useLgcyHeader = true, multisig = false, callback = false) {

        if (utils.isFunction(multisig)) {
            callback = multisig;
            multisig = false;
        }

        if (utils.isFunction(useLgcyHeader)) {
            callback = useLgcyHeader;
            useLgcyHeader = true;
            multisig = false;
        }

        if (utils.isFunction(privateKey)) {
            callback = privateKey;
            privateKey = this.weblgcy.defaultPrivateKey;
            useLgcyHeader = true;
            multisig = false;
        }


        if (!callback)
            return this.injectPromise(this.sign, transaction, privateKey, useLgcyHeader, multisig);

        // Message signing
        if (utils.isString(transaction)) {
            if (transaction.substring(0, 2) == '0x')
                transaction = transaction.substring(2);

            if (!utils.isHex(transaction))
                return callback('Expected hex message input');

            try {
                const signingKey = new Ethers.utils.SigningKey(privateKey);
                const messageBytes = [
                    ...Ethers.utils.toUtf8Bytes(useLgcyHeader ? USDL_MESSAGE_HEADER : ETH_MESSAGE_HEADER),
                    ...utils.code.hexStr2byteArray(transaction)
                ];

                const messageDigest = Ethers.utils.keccak256(messageBytes);
                const signature = signingKey.signDigest(messageDigest);

                const signatureHex = [
                    '0x',
                    signature.r.substring(2),
                    signature.s.substring(2),
                    Number(signature.v).toString(16)
                ].join('');

                return callback(null, signatureHex);
            } catch (ex) {
                callback(ex);
            }
        }

        if (!utils.isObject(transaction))
            return callback('Invalid transaction provided');

        if (!multisig && transaction.signature)
            return callback('Transaction is already signed');

        try {
            if (!multisig) {
                const address = this.weblgcy.address.toHex(
                    this.weblgcy.address.fromPrivateKey(privateKey)
                ).toLowerCase();

                if (address !== transaction.raw_data.contract[0].parameter.value.owner_address.toLowerCase())
                    return callback('Private key does not match address in transaction');
            }
            return callback(null,
                utils.crypto.signTransaction(privateKey, transaction)
            );
        } catch (ex) {
            callback(ex);
        }
    }

    sendRawTransaction(signedTransaction = false, options = {}, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (!callback)
            return this.injectPromise(this.sendRawTransaction, signedTransaction, options);

        if (!utils.isObject(signedTransaction))
            return callback('Invalid transaction provided');

        if (!utils.isObject(options))
            return callback('Invalid options provided');

        if (!signedTransaction.signature || !utils.isArray(signedTransaction.signature))
            return callback('Transaction is not signed');

        this.weblgcy.fullNode.request(
            'wallet/broadcasttransaction',
            signedTransaction,
            'post'
        ).then(result => {
            if (result.result)
                result.transaction = signedTransaction;
            callback(null, result);
        }).catch(err => callback(err));
    }

    async sendTransaction(to = false, amount = false, options = {}, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (typeof options === 'string')
            options = {privateKey: options};

        if (!callback)
            return this.injectPromise(this.sendTransaction, to, amount, options);

        if (!this.weblgcy.isAddress(to))
            return callback('Invalid recipient provided');

        if (!utils.isInteger(amount) || amount <= 0)
            return callback('Invalid amount provided');

        options = {
            privateKey: this.weblgcy.defaultPrivateKey,
            address: this.weblgcy.defaultAddress.hex,
            ...options
        };

        if (!options.privateKey && !options.address)
            return callback('Function requires either a private key or address to be set');

        try {
            const address = options.privateKey ? this.weblgcy.address.fromPrivateKey(options.privateKey) : options.address;
            /**
             * We have changed it sendTrx to sendUsdl
             */
            const transaction = await this.weblgcy.transactionBuilder.sendUsdl(to, amount, address);
            const signedTransaction = await this.sign(transaction, options.privateKey || undefined);
            const result = await this.sendRawTransaction(signedTransaction);

            return callback(null, result);
        } catch (ex) {
            return callback(ex);
        }
    }

    async sendToken(to = false, amount = false, tokenID = false, options = {}, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (typeof options === 'string')
            options = {privateKey: options};

        if (!callback)
            return this.injectPromise(this.sendToken, to, amount, tokenID, options);

        if (!this.weblgcy.isAddress(to))
            return callback('Invalid recipient provided');

        if (!utils.isInteger(amount) || amount <= 0)
            return callback('Invalid amount provided');

        if (utils.isInteger(tokenID))
            tokenID = tokenID.toString()

        if (!utils.isString(tokenID))
            return callback('Invalid token ID provided');

        options = {
            privateKey: this.weblgcy.defaultPrivateKey,
            address: this.weblgcy.defaultAddress.hex,
            ...options
        };

        if (!options.privateKey && !options.address)
            return callback('Function requires either a private key or address to be set');

        try {
            const address = options.privateKey ? this.weblgcy.address.fromPrivateKey(options.privateKey) : options.address;
            const transaction = await this.weblgcy.transactionBuilder.sendToken(to, amount, tokenID, address);
            const signedTransaction = await this.sign(transaction, options.privateKey || undefined);
            const result = await this.sendRawTransaction(signedTransaction);

            return callback(null, result);
        } catch (ex) {
            return callback(ex);
        }
    }

    /**
     * Freezes an amount of USDL.
     * Will give USDL_POWER and LGCY Power(voting rights)
     * to the owner of the frozen tokens.
     *
     * @param amount - is the number of frozen usdl
     * @param duration - is the duration in days to be frozen
     * @param resource - is the type, must be USDL_POWER"
     * @param options
     * @param callback
     */
    async freezeBalance(amount = 0, duration = 3, resource = "USDL_POWER", options = {}, receiverAddress = undefined, callback = false) {
        if (utils.isFunction(receiverAddress)) {
            callback = receiverAddress;
            receiverAddress = undefined;
        }
        if (utils.isFunction(duration)) {
            callback = duration;
            duration = 3;
        }

        if (utils.isFunction(resource)) {
            callback = resource;
            resource = "USDL_POWER";
        }

        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (typeof options === 'string')
            options = {privateKey: options};

        if (!callback)
            return this.injectPromise(this.freezeBalance, amount, duration, resource, options, receiverAddress);

        if (!['USDL_POWER'].includes(resource))
            return callback('Invalid resource provided: Expected "USDL_POWER"');

        if (!utils.isInteger(amount) || amount <= 0)
            return callback('Invalid amount provided');

        if (!utils.isInteger(duration) || duration < 3)
            return callback('Invalid duration provided, minimum of 3 days');

        options = {
            privateKey: this.weblgcy.defaultPrivateKey,
            address: this.weblgcy.defaultAddress.hex,
            ...options
        };

        if (!options.privateKey && !options.address)
            return callback('Function requires either a private key or address to be set');

        try {
            const address = options.privateKey ? this.weblgcy.address.fromPrivateKey(options.privateKey) : options.address;
            const freezeBalance = await this.weblgcy.transactionBuilder.freezeBalance(amount, duration, resource, address, receiverAddress);
            const signedTransaction = await this.sign(freezeBalance, options.privateKey || undefined);
            const result = await this.sendRawTransaction(signedTransaction);

            return callback(null, result);
        } catch (ex) {
            return callback(ex);
        }
    }

    /**
     * Unfreeze USDL that has passed the minimum freeze duration.
     * Unfreezing will USDL_POWER.
     *
     * @param resource - is the type, must be either USDL_POWER"
     * @param options
     * @param callback
     */
    async unfreezeBalance(resource = "USDL_POWER", options = {}, receiverAddress = undefined, callback = false) {
        if (utils.isFunction(receiverAddress)) {
            callback = receiverAddress;
            receiverAddress = undefined;
        }

        if (utils.isFunction(resource)) {
            callback = resource;
            resource = 'USDL_POWER';
        }

        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (typeof options === 'string')
            options = {privateKey: options};

        if (!callback)
            return this.injectPromise(this.unfreezeBalance, resource, options, receiverAddress);

        if (!['USDL_POWER'].includes(resource))
            return callback('Invalid resource provided: Expected "USDL_POWER"');

        options = {
            privateKey: this.weblgcy.defaultPrivateKey,
            address: this.weblgcy.defaultAddress.hex,
            ...options
        };

        if (!options.privateKey && !options.address)
            return callback('Function requires either a private key or address to be set');

        try {
            const address = options.privateKey ? this.weblgcy.address.fromPrivateKey(options.privateKey) : options.address;
            const unfreezeBalance = await this.weblgcy.transactionBuilder.unfreezeBalance(resource, address, receiverAddress);
            const signedTransaction = await this.sign(unfreezeBalance, options.privateKey || undefined);
            const result = await this.sendRawTransaction(signedTransaction);

            return callback(null, result);
        } catch (ex) {
            return callback(ex);
        }
    }

    /**
     * Create a new proposal
     *
     * @param parameters - is the key and amount of the proposal
     * @param options
     * @param callback
     */
    async createProposal(parameters = false, options = {}, callback = false) {
        if (utils.isFunction(options)) {
                callback = options;
                options = {};
            }
    
            if (typeof options === 'string')
                options = {privateKey: options};
        
        if (!callback)
                return this.injectPromise(this.createProposal, parameters, options);
    
        options = {
                privateKey: this.weblgcy.defaultPrivateKey,
                address: this.weblgcy.defaultAddress.hex,
                ...options
            };
    
            if (!options.privateKey && !options.address)
                return callback('Function requires either a private key or address to be set');
    
        try {
                const address = options.privateKey ? this.weblgcy.address.fromPrivateKey(options.privateKey) : options.address;
                const createProposal = await this.weblgcy.transactionBuilder.createProposal(parameters, address);
                const signedTransaction = await this.sign(createProposal, options.privateKey || undefined);
                const result = await this.sendRawTransaction(signedTransaction);
    
                return callback(null, result);
            } catch (ex) {
                return callback(ex);
            }
        
    }

    /**
     * To vote a proposal
     *
     * @param proposalID - is the id for proposal
     * @param isApproval - If true approval else false not approval
     * @param options
     * @param callback
     */
    async voteProposal(proposalID = false, isApproval = false, options = {}, callback = false) {
        if (utils.isFunction(options)) {
                callback = options;
                options = {};
            }
    
            if (typeof options === 'string')
                options = {privateKey: options};
        
        if (!callback)
                return this.injectPromise(this.voteProposal, proposalID, isApproval, options);
    
        options = {
                privateKey: this.weblgcy.defaultPrivateKey,
                address: this.weblgcy.defaultAddress.hex,
                ...options
            };
    
            if (!options.privateKey && !options.address)
                return callback('Function requires either a private key or address to be set');
    
        try {
                const address = options.privateKey ? this.weblgcy.address.fromPrivateKey(options.privateKey) : options.address;
                const voteProposal = await this.weblgcy.transactionBuilder.voteProposal(proposalID, isApproval, address);
                const signedTransaction = await this.sign(voteProposal, options.privateKey || undefined);
                const result = await this.sendRawTransaction(signedTransaction);
    
                return callback(null, result);
            } catch (ex) {
                return callback(ex);
            }
        
    }

     /**
     * To delete a proposal
     *
     * @param proposalID - is the id for proposal
     * @param options
     * @param callback
     */
    async deleteProposal(proposalID = false, options = {}, callback = false) {
        if (utils.isFunction(options)) {
                callback = options;
                options = {};
            }
    
            if (typeof options === 'string')
                options = {privateKey: options};
        
        if (!callback)
            return this.injectPromise(this.deleteProposal, proposalID, options);
    
        options = {
                privateKey: this.weblgcy.defaultPrivateKey,
                address: this.weblgcy.defaultAddress.hex,
                ...options
            };
    
            if (!options.privateKey && !options.address)
                return callback('Function requires either a private key or address to be set');
    
        try {
                const address = options.privateKey ? this.weblgcy.address.fromPrivateKey(options.privateKey) : options.address;
                const deleteProposal = await this.weblgcy.transactionBuilder.deleteProposal(proposalID, address);
                const signedTransaction = await this.sign(deleteProposal, options.privateKey || undefined);
                const result = await this.sendRawTransaction(signedTransaction);
    
                return callback(null, result);
            } catch (ex) {
                return callback(ex);
            }
        
    }

    /**
     * Create a smart contract
     *
     * @param options
     * @param issuer - Address of creater
     * @param callback
     */
    async createSmartContract(options = {}, issuer = {}, callback = false) {
        if (utils.isFunction(issuer)) {
                callback = issuer;
                issuer = {};
            }
    
            if (typeof issuer === 'string')
                issuer = {privateKey: issuer};
        
        if (!callback)
                return this.injectPromise(this.createSmartContract, options, issuer);
        
        issuer = {
                privateKey: this.weblgcy.defaultPrivateKey,
                issuer: this.weblgcy.defaultAddress.hex,
                ...issuer
            };
    
            if (!issuer.privateKey && !issuer.address)
                return callback('Function requires either a private key or address to be set');
    
        try {
                const address = issuer.privateKey ? this.weblgcy.address.fromPrivateKey(issuer.privateKey) : issuer.address;
                const createSmartContract = await this.weblgcy.transactionBuilder.createSmartContract(options, address);
                const signedTransaction = await this.sign(createSmartContract, issuer.privateKey || undefined);
                const result = await this.sendRawTransaction(signedTransaction);
    
                return callback(null, result);
            } catch (ex) {
                return callback(ex);
            }
        
    }

    /**
     * Trigger a smart contract
     *
     * @param contractAddress - Address of the deployed contract
     * @param functionSelector
     * @param options
     * @param parameters
     * @param issuerAddress - Address of creater
     * @param callback
     */
    
    async _triggerSmartContract(contractAddress, functionSelector, options = {}, parameters = [], issuerAddress = {}, callback = false) {
        if (utils.isFunction(issuerAddress)) {
            callback = issuerAddress;
            issuerAddress = {};
        }

        if (typeof issuerAddress === 'string')
        issuerAddress = {privateKey: issuerAddress};

        if (!callback)
            return this.injectPromise(this._triggerSmartContract, contractAddress, functionSelector, options, parameters,issuerAddress);
        
        if (utils.isFunction(parameters)) {
            callback = parameters;
            parameters = [];
        }

        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        issuerAddress = {
           privateKey: this.weblgcy.defaultPrivateKey,
           address: this.weblgcy.defaultAddress.hex,
           ...issuerAddress
        };

        if (!issuerAddress.privateKey && !issuerAddress.address)
           return callback('Function requires either a private key or address to be set');

        try {
           const address = issuerAddress.privateKey ? this.weblgcy.address.fromPrivateKey(issuerAddress.privateKey) : issuerAddress.address;
           const _triggerSmartContract = await this.weblgcy.transactionBuilder._triggerSmartContract(contractAddress, functionSelector, options, parameters, address);
           const signedTransaction = await this.sign(_triggerSmartContract, issuerAddress.privateKey || undefined);
           const result = await this.sendRawTransaction(signedTransaction);

           return callback(null, result);
        } catch (ex) {
           return callback(ex);
        }
    }

    /**
     * Create a Token
     *
     * @param options
     * @param issuer - Address of creater
     * @param callback
     */
    async createToken(options = {}, issuer = {}, callback = false) {
        if (utils.isFunction(issuer)) {
                callback = address;
                issuer = {};
            }
    
            if (typeof issuer === 'string')
                issuer = {privateKey: issuer};
        
        if (!callback)
                return this.injectPromise(this.createToken, options, issuer);
        
        issuer = {
                privateKey: this.weblgcy.defaultPrivateKey,
                issuer: this.weblgcy.defaultAddress.hex,
                ...issuer
            };
    
        if (!issuer.privateKey && !issuer.address)
            return callback('Function requires either a private key or address to be set');
    
        try {
                const address = issuer.privateKey ? this.weblgcy.address.fromPrivateKey(issuer.privateKey) : issuer.address;
                const createToken = await this.weblgcy.transactionBuilder.createToken(options, address);
                const signedTransaction = await this.sign(createToken, issuer.privateKey || undefined);
                const result = await this.sendRawTransaction(signedTransaction);
    
                return callback(null, result);
            } catch (ex) {
                return callback(ex);
            }
    }

    /**
     * Apply for super representative
     *
     * @param options
     * @param url - url of the SR
     * @param callback
     */
    async applyForSR(options = {}, url = false, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (typeof options === 'string')
            options = {privateKey: options};

        if (!callback)
            return this.injectPromise(this.applyForSR, options, url);

        options = {
            privateKey: this.weblgcy.defaultPrivateKey,
            address: this.weblgcy.defaultAddress.hex,
            ...options
        };

        if (!options.privateKey && !options.address)
            return callback('Function requires either a private key or address to be set');

        try {
            const address = options.privateKey ? this.weblgcy.address.fromPrivateKey(options.privateKey) : options.address;
            const applyForSR = await this.weblgcy.transactionBuilder.applyForSR(address, url);
            const signedTransaction = await this.sign(applyForSR, options.privateKey || undefined);
            const result = await this.sendRawTransaction(signedTransaction);

            return callback(null, result);
        } catch (ex) {
            return callback(ex);
        }
    }

    /**
     * Vote for super representative
     *
     * @param votes
     * @param options
     * @param callback
     */
    async vote(votes = {}, options = {}, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = undefined;
        }

        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (typeof options === 'string')
            options = {privateKey: options};

        if (!callback)
            return this.injectPromise(this.vote, votes, options);

        options = {
            privateKey: this.weblgcy.defaultPrivateKey,
            address: this.weblgcy.defaultAddress.hex,
            ...options
        };

        if (!options.privateKey && !options.address)
            return callback('Function requires either a private key or address to be set');

        try {
            const address = options.privateKey ? this.weblgcy.address.fromPrivateKey(options.privateKey) : options.address;
            const vote = await this.weblgcy.transactionBuilder.vote(votes, address);
            const signedTransaction = await this.sign(vote, options.privateKey || undefined);
            const result = await this.sendRawTransaction(signedTransaction);

            return callback(null, result);
        } catch (ex) {
            return callback(ex);
        }
    }

    /**
     * Get Reward
     *
     * @param address - Account address
     * @param options 
     * @param callback
    */
    async getReward(address, options = {}, callback = false) {
        options.confirmed = true;
        return this._getReward(address, options, callback);
    }

    async _getReward(address = this.weblgcy.defaultAddress.hex, options, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (utils.isFunction(address)) {
            callback = address;
            address = this.weblgcy.defaultAddress.hex;
        } else if (utils.isObject(address)) {
            options = address;
            address = this.weblgcy.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this._getReward, address, options);

        // if (this.validator.notValid([
        //     {
        //         name: 'origin',
        //         type: 'address',
        //         value: address
        //     }
        // ], callback))
        //     return;

        const data = {
            address: this.weblgcy.address.toHex(address)
        };

        this.weblgcy[options.confirmed ? 'solidityNode' : 'fullNode'].request(`wallet${options.confirmed ? 'solidity' : ''}/getReward`, data, 'post')
            .then((result = {}) => {

                if (typeof result.reward === 'undefined')
                    return callback('Not found.');

                callback(null, result.reward);
            }).catch(err => callback(err));
    }
    
    /**
     * Modify account name
     * Note: Username is allowed to edit only once.
     *
     * @param privateKey - Account private Key
     * @param accountName - name of the account
     * @param callback
     *
     * @return modified Transaction Object
     */
    async updateAccount(accountName = false, options = {}, callback = false) {
        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (typeof options === 'string')
            options = {privateKey: options};

        if (!callback) {
            return this.injectPromise(this.updateAccount, accountName, options);
        }

        if (!utils.isString(accountName) || !accountName.length) {
            return callback('Name must be a string');
        }

        options = {
            privateKey: this.weblgcy.defaultPrivateKey,
            address: this.weblgcy.defaultAddress.hex,
            ...options
        };

        if (!options.privateKey && !options.address)
            return callback('Function requires either a private key or address to be set');

        try {
            const address = options.privateKey ? this.weblgcy.address.fromPrivateKey(options.privateKey) : options.address;
            const updateAccount = await this.weblgcy.transactionBuilder.updateAccount(accountName, address);
            const signedTransaction = await this.sign(updateAccount, options.privateKey || undefined);
            const result = await this.sendRawTransaction(signedTransaction);

            return callback(null, result);
        } catch (ex) {
            return callback(ex);
        }
    }

    async triggerSmartContract(...params) {
        if (typeof params[2] !== 'object') {
            params[2] = {
                feeLimit: params[2],
                callValue: params[3]
            }
            params.splice(3, 1)
        }
        return this._triggerSmartContract(...params);
    }

    signMessage(...args) {
        return this.sign(...args);
    }

    sendAsset(...args) {
        return this.sendToken(...args);
    }

    send(...args) {
        return this.sendTransaction(...args);
    }

    sendUsdl(...args) {
        return this.sendTransaction(...args);
    }

    broadcast(...args) {
        return this.sendRawTransaction(...args);
    }

    signTransaction(...args) {
        return this.sign(...args);
    }

    /**
     * Gets a network modification proposal by ID.
     */
    getProposal(proposalID = false, callback = false) {
        if (!callback)
            return this.injectPromise(this.getProposal, proposalID);

        if (!utils.isInteger(proposalID) || proposalID < 0)
            return callback('Invalid proposalID provided');

        this.weblgcy.fullNode.request('wallet/getproposalbyid', {
            id: parseInt(proposalID),
        }, 'post').then(proposal => {
            callback(null, proposal);
        }).catch(err => callback(err));
    }

    /**
     * Lists all network modification proposals.
     */
    listProposals(callback = false) {
        if (!callback)
            return this.injectPromise(this.listProposals);

        this.weblgcy.fullNode.request('wallet/listproposals', {}, 'post').then(({proposals = []}) => {
            callback(null, proposals);
        }).catch(err => callback(err));
    }

    /**
     * Lists all parameters available for network modification proposals.
     */
    getChainParameters(callback = false) {
        if (!callback)
            return this.injectPromise(this.getChainParameters);

        this.weblgcy.fullNode.request('wallet/getchainparameters', {}, 'post').then(({chainParameter = []}) => {
            callback(null, chainParameter);
        }).catch(err => callback(err));
    }

    /**
     * Get the account resources
     */
    getAccountResources(address = this.weblgcy.defaultAddress.hex, callback = false) {
        if (!callback)
            return this.injectPromise(this.getAccountResources, address);

        if (!this.weblgcy.isAddress(address))
            return callback('Invalid address provided');

        this.weblgcy.fullNode.request('wallet/getaccountresource', {
            address: this.weblgcy.address.toHex(address),
        }, 'post').then(resources => {
            callback(null, resources);
        }).catch(err => callback(err));
    }

    /**
     * Get the exchange ID.
     */
    getExchangeByID(exchangeID = false, callback = false) {
        if (!callback)
            return this.injectPromise(this.getExchangeByID, exchangeID);

        if (!utils.isInteger(exchangeID) || exchangeID < 0)
            return callback('Invalid exchangeID provided');

        this.weblgcy.fullNode.request('wallet/getexchangebyid', {
            id: exchangeID,
        }, 'post').then(exchange => {
            callback(null, exchange);
        }).catch(err => callback(err));
    }

    /**
     * Lists the exchanges
     */
    listExchanges(callback = false) {
        if (!callback)
            return this.injectPromise(this.listExchanges);

        this.weblgcy.fullNode.request('wallet/listexchanges', {}, 'post').then(({exchanges = []}) => {
            callback(null, exchanges);
        }, 'post').catch(err => callback(err));
    }

    /**
     * Lists all network modification proposals.
     */
    listExchangesPaginated(limit = 10, offset = 0, callback = false) {
        if (utils.isFunction(offset)) {
            callback = offset;
            offset = 0;
        }
        if (utils.isFunction(limit)) {
            callback = limit;
            limit = 30;
        }
        if (!callback)
            return this.injectPromise(this.listExchanges);

        this.weblgcy.fullNode.request('wallet/listexchangespaginated', {
            limit,
            offset
        }, 'post').then(({exchanges = []}) => {
            callback(null, exchanges);
        }).catch(err => callback(err));
    }

    /**
     * Get info about thre node
     */
    getNodeInfo(callback = false) {
        if (!callback)
            return this.injectPromise(this.getNodeInfo);

        this.weblgcy.fullNode.request('wallet/getnodeinfo', {}, 'post').then(info => {
            callback(null, info);
        }, 'post').catch(err => callback(err));
    }


    getTokenListByName(tokenID = false, callback = false) {
        if (!callback)
            return this.injectPromise(this.getTokenListByName, tokenID);

        if (utils.isInteger(tokenID))
            tokenID = tokenID.toString()

        if (!utils.isString(tokenID) || !tokenID.length)
            return callback('Invalid token ID provided');

        this.weblgcy.fullNode.request('wallet/getassetissuelistbyname', {
            value: this.weblgcy.fromUtf8(tokenID)
        }, 'post').then(token => {
            if (!token.name)
                return callback('Token does not exist');

            callback(null, this._parseToken(token));
        }).catch(err => callback(err));
    }

    getTokenByID(tokenID = false, callback = false) {
        if (!callback)
            return this.injectPromise(this.getTokenByID, tokenID);

        if (utils.isInteger(tokenID))
            tokenID = tokenID.toString()

        if (!utils.isString(tokenID) || !tokenID.length)
            return callback('Invalid token ID provided');

        this.weblgcy.fullNode.request('wallet/getassetissuebyid', {
            value: tokenID
        }, 'post').then(token => {
            if (!token.name)
                return callback('Token does not exist');

            callback(null, this._parseToken(token));
        }).catch(err => callback(err));
    }

};
