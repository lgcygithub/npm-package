import Weblgcy from 'index';
import utils from 'utils';
import providers from "./providers";
import querystring from "querystring";

export default class Event {

    constructor(weblgcy = false) {
        if (!weblgcy || !(weblgcy instanceof Weblgcy))
            throw new Error('Expected instance of Weblgcy');
        this.weblgcy = weblgcy;
        this.injectPromise = utils.promiseInjector(this);
    }

    setServer(eventServer = false, healthcheck = 'healthcheck') {
        if (!eventServer)
            return this.weblgcy.eventServer = false;

        if (utils.isString(eventServer))
            eventServer = new providers.HttpProvider(eventServer);

        if (!this.weblgcy.isValidProvider(eventServer))
            throw new Error('Invalid event server provided');

        this.weblgcy.eventServer = eventServer;
        this.weblgcy.eventServer.isConnected = () => this.weblgcy.eventServer.request(healthcheck).then(() => true).catch(() => false);
    }

    getEventsByContactAddress(contractAddress = false, options = {}, callback = false) {

        let {
            sinceTimestamp,
            since,
            fromTimestamp,
            eventName,
            blockNumber,
            size,
            page,
            onlyConfirmed,
            onlyUnconfirmed,
            previousLastEventFingerprint,
            previousFingerprint,
            fingerprint,
            rawResponse,
            sort,
            filters
        } = Object.assign({
            sinceTimestamp: 0,
            eventName: false,
            blockNumber: false,
            size: 20,
            page: 1
        }, options)

        if (!callback)
            return this.injectPromise(this.getEventsByContactAddress, contractAddress, options);

        fromTimestamp = fromTimestamp || sinceTimestamp || since;

        if (!this.weblgcy.eventServer)
            return callback('No event server configured');

        const routeParams = [];

        if (!this.weblgcy.isAddress(contractAddress))
            return callback('Invalid contract address provided');

        if (eventName && !contractAddress)
            return callback('Usage of event name filtering requires a contract address');

        if (typeof fromTimestamp !== 'undefined' && !utils.isInteger(fromTimestamp))
            return callback('Invalid fromTimestamp provided');

        if (!utils.isInteger(size))
            return callback('Invalid size provided');

        if (size > 200) {
            console.warn('Defaulting to maximum accepted size: 200');
            size = 200;
        }

        if (!utils.isInteger(page))
            return callback('Invalid page provided');

        if (blockNumber && !eventName)
            return callback('Usage of block number filtering requires an event name');

        if (contractAddress)
            routeParams.push(this.weblgcy.address.fromHex(contractAddress));

        if (eventName)
            routeParams.push(eventName);

        if (blockNumber)
            routeParams.push(blockNumber);

        const qs = {
            size,
            page
        }
        if (typeof filters === 'object' && Object.keys(filters).length > 0) {
            qs.filters = JSON.stringify(filters);
        }

        if (fromTimestamp) {
            qs.fromTimestamp = qs.since = fromTimestamp;
        }

        if (onlyConfirmed)
            qs.onlyConfirmed = onlyConfirmed

        if (onlyUnconfirmed && !onlyConfirmed)
            qs.onlyUnconfirmed = onlyUnconfirmed

        if (sort)
            qs.sort = sort

        fingerprint = fingerprint || previousFingerprint || previousLastEventFingerprint
        if (fingerprint)
            qs.fingerprint = fingerprint

        return this.weblgcy.eventServer.request(`event/contract/${routeParams.join('/')}?${querystring.stringify(qs)}`).then((data = false) => {
            if (!data)
                return callback('Unknown error occurred');

            if (!utils.isArray(data))
                return callback(data);

            return callback(null,
                rawResponse === true ? data : data.map(event => utils.mapEvent(event))
            );
        }).catch(err => callback((err.response && err.response.data) || err));
    }


    getEventsByTransactionID(transactionID = false, options = {}, callback = false) {

        if (utils.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (!callback)
            return this.injectPromise(this.getEventsByTransactionID, transactionID, options);

        if (!this.weblgcy.eventServer)
            return callback('No event server configured');

        return this.weblgcy.eventServer.request(`event/transaction/${transactionID}`).then((data = false) => {
            if (!data)
                return callback('Unknown error occurred');

            if (!utils.isArray(data))
                return callback(data);

            return callback(null,
                options.rawResponse === true ? data : data.map(event => utils.mapEvent(event))
            );
        }).catch(err => callback((err.response && err.response.data) || err));
    }

}

