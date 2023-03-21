import Weblgcy from 'index';
import utils from 'utils';
import * as Ethers from 'ethers';
import Validator from 'paramValidator';

let self;

//helpers

function toHex(value) {
    return self.weblgcy.address.toHex(value);
}

function fromUtf8(value) {
    return self.weblgcy.fromUtf8(value);
}

function resultManager(transaction, callback) {
    if (transaction.Error)
        return callback(transaction.Error);

    if (transaction.result && transaction.result.message) {
        return callback(
            this.weblgcy.toUtf8(transaction.result.message)
        );
    }

    return callback(null, transaction);
}


export default class TransactionBuilder {
    constructor(weblgcy = false) {
        if (!weblgcy || !weblgcy instanceof Weblgcy)
            throw new Error('Expected instance of Weblgcy');
        self = this;
        this.weblgcy = weblgcy;
        this.injectPromise = utils.promiseInjector(this);
        this.validator = new Validator(weblgcy);
    }

    /*
        * We have changed it sendTrx to sendUsdl
    */

    sendUsdl(to = false, amount = 0, from = this.weblgcy.defaultAddress.hex, callback = false) {
        if (utils.isFunction(from)) {
            callback = from;
            from = this.weblgcy.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.sendUsdl, to, amount, from);

        // accept amounts passed as strings
        amount = parseInt(amount)

        if (this.validator.notValid([
            {
                name: 'recipient',
                type: 'address',
                value: to
            },
            {
                name: 'origin',
                type: 'address',
                value: from
            },
            {
                names: ['recipient', 'origin'],
                type: 'notEqual',
                msg: 'Cannot transfer USDL to the same account'
            },
            {
                name: 'amount',
                type: 'integer',
                gt: 0,
                value: amount
            }
        ], callback))
            return;

        this.weblgcy.fullNode.request('wallet/createtransaction', {
            to_address: toHex(to),
            owner_address: toHex(from),
            amount: amount
        }, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    sendToken(to = false, amount = 0, tokenID = false, from = this.weblgcy.defaultAddress.hex, callback = false) {
        if (utils.isFunction(from)) {
            callback = from;
            from = this.weblgcy.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.sendToken, to, amount, tokenID, from);

        amount = parseInt(amount)
        if (this.validator.notValid([
            {
                name: 'recipient',
                type: 'address',
                value: to
            },
            {
                name: 'origin',
                type: 'address',
                value: from,
            },
            {
                names: ['recipient', 'origin'],
                type: 'notEqual',
                msg: 'Cannot transfer tokens to the same account'
            },
            {
                name: 'amount',
                type: 'integer',
                gt: 0,
                value: amount
            },
            {
                name: 'token ID',
                type: 'tokenId',
                value: tokenID
            }
        ], callback))
            return;

        this.weblgcy.fullNode.request('wallet/transferasset', {
            to_address: toHex(to),
            owner_address: toHex(from),
            asset_name: fromUtf8(tokenID),
            amount: parseInt(amount)
        }, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    purchaseToken(issuerAddress = false, tokenID = false, amount = 0, buyer = this.weblgcy.defaultAddress.hex, callback = false) {
        if (utils.isFunction(buyer)) {
            callback = buyer;
            buyer = this.weblgcy.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.purchaseToken, issuerAddress, tokenID, amount, buyer);

        if (!this.weblgcy.isAddress(issuerAddress))
            return callback('Invalid issuer address provided');

        if (!utils.isString(tokenID) || !tokenID.length)
            return callback('Invalid token ID provided');

        if (!utils.isInteger(amount) || amount <= 0)
            return callback('Invalid amount provided');

        if (!this.weblgcy.isAddress(buyer))
            return callback('Invalid buyer address provided');

        this.weblgcy.fullNode.request('wallet/participateassetissue', {
            to_address: toHex(issuerAddress),
            owner_address: toHex(buyer),
            asset_name: fromUtf8(tokenID),
            amount: parseInt(amount)
        }, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    freezeBalance(amount = 0, duration = 3, resource = "USDL_POWER", address = this.weblgcy.defaultAddress.hex, receiverAddress = undefined, callback = false) {
        if (utils.isFunction(receiverAddress)) {
            callback = receiverAddress;
            receiverAddress = undefined;
        }

        if (utils.isFunction(address)) {
            callback = address;
            address = this.weblgcy.defaultAddress.hex;
        }

        if (utils.isFunction(duration)) {
            callback = duration;
            duration = 3;
        }

        if (utils.isFunction(resource)) {
            callback = resource;
            resource = "USDL_POWER";
        }

        if (!callback)
            return this.injectPromise(this.freezeBalance, amount, duration, resource, address, receiverAddress);

        if (!['USDL_POWER'].includes(resource))
            return callback('Invalid resource provided: Expected "USDL_POWER"');

        if (!utils.isInteger(amount) || amount <= 0)
            return callback('Invalid amount provided');

        if (!utils.isInteger(duration) || duration < 3)
            return callback('Invalid duration provided, minimum of 3 days');

        if (!this.weblgcy.isAddress(address))
            return callback('Invalid address provided');

        // here set `optional: true` in notValid param
        if (utils.isNotNullOrUndefined(receiverAddress) && !this.weblgcy.isAddress(receiverAddress))
            return callback('Invalid receiver address provided');

        const data = {
            owner_address: toHex(address),
            frozen_balance: parseInt(amount),
            frozen_duration: parseInt(duration),
            resource: resource
        }

        if (utils.isNotNullOrUndefined(receiverAddress)) {
            data.receiver_address = toHex(receiverAddress)
        }

        this.weblgcy.fullNode.request('wallet/freezebalance', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    unfreezeBalance(resource = "USDL_POWER", address = this.weblgcy.defaultAddress.hex, receiverAddress = undefined, callback = false) {
        if (utils.isFunction(receiverAddress)) {
            callback = receiverAddress;
            receiverAddress = undefined;
        }

        if (utils.isFunction(address)) {
            callback = address;
            address = this.weblgcy.defaultAddress.hex;
        }

        if (utils.isFunction(resource)) {
            callback = resource;
            resource = "USDL_POWER";
        }

        if (!callback)
            return this.injectPromise(this.unfreezeBalance, resource, address, receiverAddress);

        if (!['USDL_POWER'].includes(resource))
            return callback('Invalid resource provided: Expected "USDL_POWER"');

        if (!this.weblgcy.isAddress(address))
            return callback('Invalid address provided');

        if (utils.isNotNullOrUndefined(receiverAddress) && !this.weblgcy.isAddress(receiverAddress))
            return callback('Invalid receiver address provided');

        const data = {
            owner_address: toHex(address),
            resource: resource
        }

        if (utils.isNotNullOrUndefined(receiverAddress)) {
            data.receiver_address = toHex(receiverAddress)
        }

        this.weblgcy.fullNode.request('wallet/unfreezebalance', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    withdrawBlockRewards(address = this.weblgcy.defaultAddress.hex, callback = false) {
        if (utils.isFunction(address)) {
            callback = address;
            address = this.weblgcy.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.withdrawBlockRewards, address);

        if (!this.weblgcy.isAddress(address))
            return callback('Invalid address provided');

        this.weblgcy.fullNode.request('wallet/withdrawbalance', {
            owner_address: toHex(address)
        }, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    applyForSR(address = this.weblgcy.defaultAddress.hex, url = false, callback = false) {
        if (utils.isValidURL(address)) {
            callback = url || false;
            url = address;
            address = this.weblgcy.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.applyForSR, address, url);

        if (!this.weblgcy.isAddress(address))
            return callback('Invalid address provided');

        if (!utils.isValidURL(url))
            return callback('Invalid url provided');

        this.weblgcy.fullNode.request('wallet/createwitness', {
            owner_address: toHex(address),
            url: fromUtf8(url)
        }, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    vote(votes = {}, voterAddress = this.weblgcy.defaultAddress.hex, callback = false) {
        if (utils.isFunction(voterAddress)) {
            callback = voterAddress;
            voterAddress = this.weblgcy.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.vote, votes, voterAddress);

        if (this.validator.notValid([
            {
                name: 'voter',
                type: 'address',
                value: voterAddress
            },
            {
                name: 'votes',
                type: 'notEmptyObject',
                value: votes
            }
        ], callback))
            return;

        let invalid = false;

        votes = Object.entries(votes).map(([srAddress, voteCount]) => {
            if (invalid)
                return;

            if (this.validator.notValid([
                {
                    name: 'SR',
                    type: 'address',
                    value: srAddress
                },
                {
                    name: 'vote count',
                    type: 'integer',
                    gt: 0,
                    value: voteCount,
                    msg: 'Invalid vote count provided for SR: ' + srAddress
                }
            ]))
                return invalid = true;

            return {
                vote_address: toHex(srAddress),
                vote_count: parseInt(voteCount)
            };
        });

        if (invalid)
            return;

        this.weblgcy.fullNode.request('wallet/votewitnessaccount', {
            owner_address: toHex(voterAddress),
            votes
        }, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    createSmartContract(options = {}, issuerAddress = this.weblgcy.defaultAddress.hex, callback = false) {
        if (utils.isFunction(issuerAddress)) {
            callback = issuerAddress;
            issuerAddress = this.weblgcy.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.createSmartContract, options, issuerAddress);

        const feeLimit = options.feeLimit || 1_000_000_000;
        let userFeePercentage = options.userFeePercentage;
        if (typeof userFeePercentage !== 'number' || !userFeePercentage) {
            userFeePercentage = 100;
        }
        const originKandyLimit = options.originKandyLimit || 10_000_000;
        const callValue = options.callValue || 0;
        const tokenValue = options.tokenValue;
        const tokenId = options.tokenId || options.token_id;

        let {
            abi = false,
            bytecode = false,
            parameters = [],
            name = ""
        } = options;


        if (abi && utils.isString(abi)) {
            try {
                abi = JSON.parse(abi);
            } catch {
                return callback('Invalid options.abi provided');
            }
        }

        if (!utils.isArray(abi))
            return callback('Invalid options.abi provided in array');


        const payable = abi.some(func => {
            return func.type == 'constructor' && func.payable;
        });

        if (!utils.isHex(bytecode))
            return callback('Invalid options.bytecode provided');

        if (!utils.isInteger(feeLimit) || feeLimit <= 0 || feeLimit > 1_000_000_000)
            return callback('Invalid options.feeLimit provided');
        // {
        //     name: 'fee limit',
        //     type: 'integer',
        //     gt: 0,
        //     lte: 1_000_000_000,
        //     value: feeLimit
        // }

        if (!utils.isInteger(callValue) || callValue < 0)
            return callback('Invalid options.callValue provided');

        if (payable && callValue == 0)
            return callback('When contract is payable, options.callValue must be a positive integer');

        if (!payable && callValue > 0)
            return callback('When contract is not payable, options.callValue must be 0');

        if (!utils.isInteger(userFeePercentage) || userFeePercentage < 0 || userFeePercentage > 100)
            return callback('Invalid options.userFeePercentage provided');

        if (!utils.isInteger(originKandyLimit) || originKandyLimit < 0 || originKandyLimit > 10_000_000)
            return callback('Invalid options.originKandyLimit provided');

        if (!utils.isArray(parameters))
            return callback('Invalid parameters provided');

        if (!this.weblgcy.isAddress(issuerAddress))
            return callback('Invalid issuer address provided');

        var constructorParams = abi.find(
            (it) => {
                return it.type === 'constructor';
            }
        );

        if (utils.isNotNullOrUndefined(tokenValue) && (!utils.isInteger(tokenValue) || tokenValue < 0))
            return callback('Invalid options.tokenValue provided');

        if (utils.isNotNullOrUndefined(tokenId) && (!utils.isInteger(tokenId) || tokenId < 0))
            return callback('Invalid options.tokenValue provided');

        if (typeof constructorParams !== 'undefined' && constructorParams) {
            const abiCoder = new Ethers.utils.AbiCoder();
            const types = [];
            const values = [];
            constructorParams = constructorParams.inputs;

            if (parameters.length != constructorParams.length)
                return callback(`constructor needs ${constructorParams.length} but ${parameters.length} provided`);

            for (let i = 0; i < parameters.length; i++) {
                let type = constructorParams[i].type;
                let value = parameters[i];

                if (!type || !utils.isString(type) || !type.length)
                    return callback('Invalid parameter type provided: ' + type);

                if (type == 'address')
                    value = toHex(value).replace(/^(30)/, '0x');

                types.push(type);
                values.push(value);
            }

            try {
                parameters = abiCoder.encode(types, values).replace(/^(0x)/, '');
            } catch (ex) {
                return callback(ex);
            }
        } else parameters = '';

        const args = {
            owner_address: toHex(issuerAddress),
            fee_limit: parseInt(feeLimit),
            call_value: parseInt(callValue),
            consume_user_resource_percent: userFeePercentage,
            origin_kandy_limit: originKandyLimit,
            abi: JSON.stringify(abi),
            bytecode,
            parameter: parameters,
            name
        }

        // tokenValue and tokenId can cause errors if provided when the usdl10 proposal has not been approved yet. So we set them only if they are passed to the method.
        if (utils.isNotNullOrUndefined(tokenValue))
            args.call_token_value = parseInt(tokenValue)
        if (utils.isNotNullOrUndefined(tokenId))
            args.token_id = parseInt(tokenId)

        this.weblgcy.fullNode.request('wallet/deploycontract', args, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    triggerSmartContract(...params) {
        if (typeof params[2] !== 'object') {
            params[2] = {
                feeLimit: params[2],
                callValue: params[3]
            }
            params.splice(3, 1)
        }
        return this._triggerSmartContract(...params);
    }

    triggerConstantContract(...params) {
        params[2]._isConstant = true
        return this._triggerSmartContract(...params);
    }

    triggerConfirmedConstantContract(...params) {
        params[2]._isConstant = true
        params[2].confirmed = true
        return this.triggerSmartContract(...params);
    }

    _triggerSmartContract(
        contractAddress,
        functionSelector,
        options = {},
        parameters = [],
        issuerAddress = this.weblgcy.defaultAddress.hex,
        callback = false
    ) {

        if (utils.isFunction(issuerAddress)) {
            callback = issuerAddress;
            issuerAddress = this.weblgcy.defaultAddress.hex;
        }

        if (utils.isFunction(parameters)) {
            callback = parameters;
            parameters = [];
        }

        if (!callback) {
            return this.injectPromise(
                this._triggerSmartContract,
                contractAddress,
                functionSelector,
                options,
                parameters,
                issuerAddress
            );
        }

        let {
            tokenValue,
            tokenId,
            callValue,
            feeLimit
        } = Object.assign({
            callValue: 0,
            feeLimit: 1_000_000_000
        }, options)

        if (utils.isNotNullOrUndefined(tokenValue) && (!utils.isInteger(tokenValue) || tokenValue < 0))
            return callback('Invalid options.tokenValue provided');

        if (utils.isNotNullOrUndefined(tokenId) && (!utils.isInteger(tokenId) || tokenId < 0))
            return callback('Invalid options.tokenValue provided');

        if (!this.weblgcy.isAddress(contractAddress))
            return callback('Invalid contract address provided');

        if (!utils.isString(functionSelector) || !functionSelector.length)
            return callback('Invalid function selector provided');

        if (!utils.isInteger(callValue) || callValue < 0)
            return callback('Invalid call value provided');

        if (!utils.isInteger(feeLimit) || feeLimit <= 0 || feeLimit > 1_000_000_000)
            return callback('Invalid fee limit provided');

        if (!utils.isArray(parameters))
            return callback('Invalid parameters provided');

        if (issuerAddress !== false && !this.weblgcy.isAddress(issuerAddress))
            return callback('Invalid issuer address provided');

        functionSelector = functionSelector.replace('/\s*/g', '');

        if (parameters.length) {
            const abiCoder = new Ethers.utils.AbiCoder();
            let types = [];
            const values = [];

            for (let i = 0; i < parameters.length; i++) {
                let { type, value } = parameters[i];

                if (!type || !utils.isString(type) || !type.length)
                    return callback('Invalid parameter type provided: ' + type);

                if (type == 'address')
                    value = toHex(value).replace(/^(30)/, '0x');

                types.push(type);
                values.push(value);
            }

            try {
                // workaround for unsupported trcToken type
                types = types.map(type => {
                    if (/trcToken/.test(type)) {
                        type = type.replace(/trcToken/, 'uint256')
                    }
                    return type
                })

                parameters = abiCoder.encode(types, values).replace(/^(0x)/, '');
            } catch (ex) {
                return callback(ex);
            }
        } else parameters = '';

        const args = {
            contract_address: toHex(contractAddress),
            owner_address: toHex(issuerAddress),
            function_selector: functionSelector,
            fee_limit: parseInt(feeLimit),
            call_value: parseInt(callValue),
            parameter: parameters
        };

        if (utils.isNotNullOrUndefined(tokenValue))
            args.call_token_value = parseInt(tokenValue)
        if (utils.isNotNullOrUndefined(tokenId))
            args.token_id = parseInt(tokenId)

        this.weblgcy.fullNode.request('wallet/triggersmartcontract', args, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }


    createToken(options = {}, issuerAddress = this.weblgcy.defaultAddress.hex, callback = false) {
        if (utils.isFunction(issuerAddress)) {
            callback = issuerAddress;
            issuerAddress = this.weblgcy.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.createToken, options, issuerAddress);

        const {
            name = false,
            abbreviation = false,
            description = false,
            url = false,
            totalSupply = 0,
            usdlRatio = 1, // How much USDL will `tokenRatio` cost?
            tokenRatio = 1, // How many tokens will `usdlRatio` afford?
            saleStart = Date.now(),
            saleEnd = false,
            freeBandwidth = 0, // The creator's "donated" bandwidth for use by token holders
            freeBandwidthLimit = 0, // Out of `totalFreeBandwidth`, the amount each token holder get
            frozenAmount = 0,
            frozenDuration = 0,
            // for now there is no default for the following values
            voteScore,
            precision
        } = options;

        if (!utils.isString(name) || !name.length)
            return callback('Invalid token name provided');

        if (!utils.isString(abbreviation) || !abbreviation.length)
            return callback('Invalid token abbreviation provided');

        if (!utils.isInteger(totalSupply) || totalSupply <= 0)
            return callback('Invalid supply amount provided');

        if (!utils.isInteger(usdlRatio) || usdlRatio <= 0)
            return callback('USDL ratio must be a positive integer');

        if (!utils.isInteger(tokenRatio) || tokenRatio <= 0)
            return callback('Token ratio must be a positive integer');

        if (!utils.isInteger(saleStart) || saleStart < Date.now())
            return callback('Invalid sale start timestamp provided');

        if (!utils.isInteger(saleEnd) || saleEnd <= saleStart)
            return callback('Invalid sale end timestamp provided');

        if (!utils.isString(description) || !description.length)
            return callback('Invalid token description provided');

        if (!utils.isString(url) || !url.length || !utils.isValidURL(url))
            return callback('Invalid token url provided');

        if (!utils.isInteger(freeBandwidth) || freeBandwidth < 0)
            return callback('Invalid free bandwidth amount provided');

        if (!utils.isInteger(freeBandwidthLimit) || freeBandwidthLimit < 0 || (freeBandwidth && !freeBandwidthLimit))
            return callback('Invalid free bandwidth limit provided');

        if (!utils.isInteger(frozenAmount) || frozenAmount < 0 || (!frozenDuration && frozenAmount))
            return callback('Invalid frozen supply provided');

        if (!utils.isInteger(frozenDuration) || frozenDuration < 0 || (frozenDuration && !frozenAmount))
            return callback('Invalid frozen duration provided');

        if (!this.weblgcy.isAddress(issuerAddress))
            return callback('Invalid issuer address provided');

        if (utils.isNotNullOrUndefined(voteScore) && (!utils.isInteger(voteScore) || voteScore <= 0))
            return callback('voteScore must be a positive integer greater than 0');

        if (utils.isNotNullOrUndefined(precision) && (!utils.isInteger(precision) || precision <= 0 || precision > 18))
            return callback('precision must be a positive integer > 0 and <= 18');

        const data = {
            owner_address: toHex(issuerAddress),
            name: fromUtf8(name),
            abbr: fromUtf8(abbreviation),
            description: fromUtf8(description),
            url: fromUtf8(url),
            total_supply: parseInt(totalSupply),
            lgcy_num: parseInt(usdlRatio), //lgcy_num
            num: parseInt(tokenRatio),
            start_time: parseInt(saleStart),
            end_time: parseInt(saleEnd),
            free_asset_net_limit: parseInt(freeBandwidth),
            public_free_asset_net_limit: parseInt(freeBandwidthLimit),
            frozen_supply: {
                frozen_amount: parseInt(frozenAmount),
                frozen_days: parseInt(frozenDuration)
            }
        }
        if (precision && !isNaN(parseInt(precision))) {
            data.precision = parseInt(precision);
        }
        if (voteScore && !isNaN(parseInt(voteScore))) {
            data.vote_score = parseInt(voteScore)
        }

        this.weblgcy.fullNode.request('wallet/createassetissue', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    updateAccount(accountName = false, address = this.weblgcy.defaultAddress.hex, callback = false) {
        if (utils.isFunction(address)) {
            callback = address;
            address = this.weblgcy.defaultAddress.hex;
        }

        if (!callback) {
            return this.injectPromise(this.updateAccount, accountName, address);
        }

        if (!utils.isString(accountName) || !accountName.length) {
            return callback('Name must be a string');
        }

        if (!this.weblgcy.isAddress(address)) {
            return callback('Invalid origin address provided');
        }

        this.weblgcy.fullNode.request('wallet/updateaccount', {
            account_name: fromUtf8(accountName),
            owner_address: toHex(address),
        }, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    updateToken(options = {}, issuerAddress = this.weblgcy.defaultAddress.hex, callback = false) {
        if (utils.isFunction(issuerAddress)) {
            callback = issuerAddress;
            issuerAddress = this.weblgcy.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.updateToken, options, issuerAddress);

        const {
            description = false,
            url = false,
            freeBandwidth = 0, // The creator's "donated" bandwidth for use by token holders
            freeBandwidthLimit = 0 // Out of `totalFreeBandwidth`, the amount each token holder get
        } = options;

        if (!utils.isString(description) || !description.length)
            return callback('Invalid token description provided');

        if (!utils.isString(url) || !url.length || !utils.isValidURL(url))
            return callback('Invalid token url provided');

        if (!utils.isInteger(freeBandwidth) || freeBandwidth < 0)
            return callback('Invalid free bandwidth amount provided');

        if (!utils.isInteger(freeBandwidthLimit) || freeBandwidthLimit < 0 || (freeBandwidth && !freeBandwidthLimit))
            return callback('Invalid free bandwidth limit provided');

        if (!this.weblgcy.isAddress(issuerAddress))
            return callback('Invalid issuer address provided');

        this.weblgcy.fullNode.request('wallet/updateasset', {
            owner_address: toHex(issuerAddress),
            description: fromUtf8(description),
            url: fromUtf8(url),
            new_limit: parseInt(freeBandwidth),
            new_public_limit: parseInt(freeBandwidthLimit)
        }, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    sendAsset(...args) {
        return this.sendToken(...args);
    }

    purchaseAsset(...args) {
        return this.purchaseToken(...args);
    }

    createAsset(...args) {
        return this.createToken(...args);
    }

    updateAsset(...args) {
        return this.updateToken(...args);
    }

    /**
     * Creates a proposal to modify the network.
     * Can only be created by a current Super Representative.
     */
    createProposal(parameters = false, issuerAddress = this.weblgcy.defaultAddress.hex, callback = false) {
        if (utils.isFunction(issuerAddress)) {
            callback = issuerAddress;
            issuerAddress = this.weblgcy.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.createProposal, parameters, issuerAddress);

        if (!this.weblgcy.isAddress(issuerAddress))
            return callback('Invalid issuerAddress provided');

        const invalid = 'Invalid proposal parameters provided';

        if (!parameters)
            return callback(invalid);

        if (!utils.isArray(parameters))
            parameters = [parameters];

        for (let parameter of parameters) {
            if (!utils.isObject(parameter))
                return callback(invalid);
        }

        this.weblgcy.fullNode.request('wallet/proposalcreate', {
            owner_address: toHex(issuerAddress),
            parameters: parameters
        }, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    /**
     * Deletes a network modification proposal that the owner issued.
     * Only current Super Representative can vote on a proposal.
     */
    deleteProposal(proposalID = false, issuerAddress = this.weblgcy.defaultAddress.hex, callback = false) {
        if (utils.isFunction(issuerAddress)) {
            callback = issuerAddress;
            issuerAddress = this.weblgcy.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.deleteProposal, proposalID, issuerAddress);

        if (!this.weblgcy.isAddress(issuerAddress))
            return callback('Invalid issuerAddress provided');

        if (!utils.isInteger(proposalID) || proposalID < 0)
            return callback('Invalid proposalID provided');

        this.weblgcy.fullNode.request('wallet/proposaldelete', {
            owner_address: toHex(issuerAddress),
            proposal_id: parseInt(proposalID)
        }, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    /**
     * Adds a vote to an issued network modification proposal.
     * Only current Super Representative can vote on a proposal.
     */
    voteProposal(proposalID = false, isApproval = false, voterAddress = this.weblgcy.defaultAddress.hex, callback = false) {
        if (utils.isFunction(voterAddress)) {
            callback = voterAddress;
            voterAddress = this.weblgcy.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.voteProposal, proposalID, isApproval, voterAddress);

        if (!this.weblgcy.isAddress(voterAddress))
            return callback('Invalid voterAddress address provided');

        if (!utils.isInteger(proposalID) || proposalID < 0)
            return callback('Invalid proposalID provided');

        if (!utils.isBoolean(isApproval))
            return callback('Invalid hasApproval provided');

        this.weblgcy.fullNode.request('wallet/proposalapprove', {
            owner_address: toHex(voterAddress),
            proposal_id: parseInt(proposalID),
            is_add_approval: isApproval
        }, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    createUSDLExchange(tokenName, tokenBalance, usdlBalance, ownerAddress = this.weblgcy.defaultAddress.hex, callback = false) {
        if (utils.isFunction(ownerAddress)) {
            callback = ownerAddress;
            ownerAddress = this.weblgcy.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.createUSDLExchange, tokenName, tokenBalance, usdlBalance, ownerAddress);

        if (!this.weblgcy.isAddress(ownerAddress))
            return callback('Invalid address provided');

        if (!utils.isString(tokenName) || !tokenName.length)
            return callback('Invalid tokenName provided');

        if (!utils.isInteger(tokenBalance) || tokenBalance <= 0
            || !utils.isInteger(usdlBalance) || usdlBalance <= 0)
            return callback('Invalid amount provided');

        this.weblgcy.fullNode.request('wallet/exchangecreate', {
            owner_address: toHex(ownerAddress),
            first_token_id: fromUtf8(tokenName),
            first_token_balance: tokenBalance,
            second_token_id: '5f', // Constant for USDL.
            second_token_balance: usdlBalance
        }, 'post').then(resources => {
            callback(null, resources);
        }).catch(err => callback(err));
    }

    createTokenExchange(firstTokenName, firstTokenBalance, secondTokenName, secondTokenBalance, ownerAddress = this.weblgcy.defaultAddress.hex, callback = false) {
        if (utils.isFunction(ownerAddress)) {
            callback = ownerAddress;
            ownerAddress = this.weblgcy.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.createTokenExchange, firstTokenName, firstTokenBalance, secondTokenName, secondTokenBalance, ownerAddress);

        if (!this.weblgcy.isAddress(ownerAddress))
            return callback('Invalid address provided');

        if (!utils.isString(firstTokenName) || !firstTokenName.length)
            return callback('Invalid firstTokenName provided');

        if (!utils.isString(secondTokenName) || !secondTokenName.length)
            return callback('Invalid secondTokenName provided');

        if (!utils.isInteger(firstTokenBalance) || firstTokenBalance <= 0
            || !utils.isInteger(secondTokenBalance) || secondTokenBalance <= 0)
            return callback('Invalid amount provided');

        this.weblgcy.fullNode.request('wallet/exchangecreate', {
            owner_address: toHex(ownerAddress),
            first_token_id: fromUtf8(firstTokenName),
            first_token_balance: firstTokenBalance,
            second_token_id: fromUtf8(secondTokenName),
            second_token_balance: secondTokenBalance
        }, 'post').then(resources => {
            callback(null, resources);
        }).catch(err => callback(err));
    }

    /**
     * Adds tokens into a bancor style exchange.
     * Will add both tokens at market rate.
     * Use "_" for the constant value for USDL.
     */
    injectExchangeTokens(exchangeID = false, tokenName = false, tokenAmount = 0, ownerAddress = this.weblgcy.defaultAddress.hex, callback = false) {
        if (utils.isFunction(ownerAddress)) {
            callback = ownerAddress;
            ownerAddress = this.weblgcy.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.injectExchangeTokens, exchangeID, tokenName, tokenAmount, ownerAddress);

        if (!this.weblgcy.isAddress(ownerAddress))
            return callback('Invalid ownerAddress provided');

        if (!utils.isInteger(exchangeID) || exchangeID < 0)
            return callback('Invalid exchangeID provided');

        if (!utils.isString(tokenName) || !tokenName.length)
            return callback('Invalid tokenName provided');

        if (!utils.isInteger(tokenAmount) || tokenAmount < 1)
            return callback('Invalid tokenAmount provided');

        this.weblgcy.fullNode.request('wallet/exchangeinject', {
            owner_address: toHex(ownerAddress),
            exchange_id: parseInt(exchangeID),
            token_id: fromUtf8(tokenName),
            quant: parseInt(tokenAmount)
        }, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    /**
     * Withdraws tokens from a bancor style exchange.
     * Will withdraw at market rate both tokens.
     * Use "_" for the constant value for USDL.
     */
    withdrawExchangeTokens(exchangeID = false, tokenName = false, tokenAmount = 0, ownerAddress = this.weblgcy.defaultAddress.hex, callback = false) {
        if (utils.isFunction(ownerAddress)) {
            callback = ownerAddress;
            ownerAddress = this.weblgcy.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.withdrawExchangeTokens, exchangeID, tokenName, tokenAmount, ownerAddress);

        if (!this.weblgcy.isAddress(ownerAddress))
            return callback('Invalid ownerAddress provided');

        if (!utils.isInteger(exchangeID) || exchangeID < 0)
            return callback('Invalid exchangeID provided');

        if (!utils.isString(tokenName) || !tokenName.length)
            return callback('Invalid tokenName provided');

        if (!utils.isInteger(tokenAmount) || tokenAmount < 1)
            return callback('Invalid tokenAmount provided');

        this.weblgcy.fullNode.request('wallet/exchangewithdraw', {
            owner_address: toHex(ownerAddress),
            exchange_id: parseInt(exchangeID),
            token_id: fromUtf8(tokenName),
            quant: parseInt(tokenAmount)
        }, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    /**
     * Trade tokens on a bancor style exchange.
     * Expected value is a validation and used to cap the total amt of token 2 spent.
     * Use "_" for the constant value for USDL.
     */
    tradeExchangeTokens(exchangeID = false,
        tokenName = false,
        tokenAmountSold = 0,
        tokenAmountExpected = 0,
        ownerAddress = this.weblgcy.defaultAddress.hex,
        callback = false) {
        if (utils.isFunction(ownerAddress)) {
            callback = ownerAddress;
            ownerAddress = this.weblgcy.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.tradeExchangeTokens, exchangeID, tokenName, tokenAmountSold, tokenAmountExpected, ownerAddress);

        if (!this.weblgcy.isAddress(ownerAddress))
            return callback('Invalid ownerAddress provided');

        if (!utils.isInteger(exchangeID) || exchangeID < 0)
            return callback('Invalid exchangeID provided');

        if (!utils.isString(tokenName) || !tokenName.length)
            return callback('Invalid tokenName provided');

        if (!utils.isInteger(tokenAmountSold) || tokenAmountSold < 1)
            return callback('Invalid tokenAmountSold provided');

        if (!utils.isInteger(tokenAmountExpected) || tokenAmountExpected < 1)
            return callback('Invalid tokenAmountExpected provided');

        this.weblgcy.fullNode.request('wallet/exchangetransaction', {
            owner_address: toHex(ownerAddress),
            exchange_id: parseInt(exchangeID),
            token_id: this.weblgcy.fromAscii(tokenName),
            quant: parseInt(tokenAmountSold),
            expected: parseInt(tokenAmountExpected)
        }, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    /**
     * Update userFeePercentage.
     */
    updateSetting(contractAddress = false,
        userFeePercentage = false,
        ownerAddress = this.weblgcy.defaultAddress.hex,
        callback = false) {

        if (utils.isFunction(ownerAddress)) {
            callback = ownerAddress;
            ownerAddress = this.weblgcy.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.updateSetting, contractAddress, userFeePercentage, ownerAddress);

        if (!this.weblgcy.isAddress(ownerAddress))
            return callback('Invalid ownerAddress provided');

        if (!this.weblgcy.isAddress(contractAddress))
            return callback('Invalid contractAddress provided');

        if (!utils.isInteger(userFeePercentage) || userFeePercentage < 0 || userFeePercentage > 100)
            return callback('Invalid options.userFeePercentage provided');

        this.weblgcy.fullNode.request('wallet/updatesetting', {
            owner_address: toHex(ownerAddress),
            contract_address: toHex(contractAddress),
            consume_user_resource_percent: userFeePercentage
        }, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    /**
     * Update kandy limit.
     */
    updateKandyLimit(contractAddress = false,
        originKandyLimit = false,
        ownerAddress = this.weblgcy.defaultAddress.hex,
        callback = false) {

        if (utils.isFunction(ownerAddress)) {
            callback = ownerAddress;
            ownerAddress = this.weblgcy.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.updateKandyLimit, contractAddress, originKandyLimit, ownerAddress);

        if (!this.weblgcy.isAddress(ownerAddress))
            return callback('Invalid ownerAddress provided');

        if (!this.weblgcy.isAddress(contractAddress))
            return callback('Invalid contractAddress provided');

        if (!utils.isInteger(originKandyLimit) || originKandyLimit < 0 || originKandyLimit > 10_000_000)
            return callback('Invalid options.originKandyLimit provided');

        this.weblgcy.fullNode.request('wallet/updatekandylimit', {
            owner_address: toHex(ownerAddress),
            contract_address: toHex(contractAddress),
            origin_kandy_limit: originKandyLimit
        }, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    checkPermissions(permissions, type) {
        if (permissions) {
            if (permissions.type !== type
                || !permissions.permission_name
                || !utils.isString(permissions.permission_name)
                || !utils.isInteger(permissions.threshold)
                || permissions.threshold < 1
                || !permissions.keys
            ) {
                return false
            }
            for (let key of permissions.key) {
                if (!this.weblgcy.isAddress(key.address)
                    || !utils.isInteger(key.weight)
                    || key.weight > permissions.threshold
                    || key.weight < 1
                    || (type === 2 && !permissions.operations)
                ) {
                    return false
                }
            }
        }
        return true
    }

    updateAccountPermissions(ownerAddress = this.weblgcy.defaultAddress.hex,
        ownerPermissions = false,
        witnessPermissions = false,
        activesPermissions = false,
        callback = false) {

        if (utils.isFunction(activesPermissions)) {
            callback = activesPermissions;
            activesPermissions = false;
        }

        if (utils.isFunction(witnessPermissions)) {
            callback = witnessPermissions;
            witnessPermissions = activesPermissions = false;
        }

        if (utils.isFunction(ownerPermissions)) {
            callback = ownerPermissions;
            ownerPermissions = witnessPermissions = activesPermissions = false;
        }

        if (!callback)
            return this.injectPromise(this.updateAccountPermissions, ownerAddress, ownerPermissions, witnessPermissions, activesPermissions);

        if (!this.weblgcy.isAddress(ownerAddress))
            return callback('Invalid ownerAddress provided');

        if (!this.checkPermissions(ownerPermissions, 0)) {
            return callback('Invalid ownerPermissions provided');
        }

        if (!this.checkPermissions(witnessPermissions, 1)) {
            return callback('Invalid witnessPermissions provided');
        }

        if (!Array.isArray(activesPermissions)) {
            activesPermissions = [activesPermissions]
        }

        for (let activesPermission of activesPermissions) {
            if (!this.checkPermissions(activesPermission, 2)) {
                return callback('Invalid activesPermissions provided');
            }
        }

        const data = {
            owner_address: ownerAddress
        }
        if (ownerPermissions) {
            data.owner = ownerPermissions
        }
        if (witnessPermissions) {
            data.witness = witnessPermissions
        }
        if (activesPermissions) {
            data.actives = activesPermissions.length === 1 ? activesPermissions[0] : activesPermissions
        }

        this.weblgcy.fullNode.request('wallet/accountpermissionupdate', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }


}
