## What is Weblgcy?

Weblgcy aims to deliver a unified, seamless development experience influenced by Ethereum's [Web3](https://github.com/ethereum/web3.js/) implementation.

## Compatibility
- Version built for Node.js v6 and above

You can access either version specifically from the [dist](dist) folder.

Weblgcy is also compatible with frontend frameworks such as:
- Angular 
- React
- Vue.

## Installation

### Node.js
```bash
npm install weblgcy
```

### Browser
First, don't use the release section of this repo, it has not updated in a long time.

Then easiest way to use Weblgcy in a browser is to install it as above and copy the dist file to your working folder. For example:
```
cp node_modules/weblgcy/dist/Weblgcy.js ./js/weblgcy.js
```
so that you can call it in your HTML page as
```
<script src="./js/weblgcy.js"><script>
```

## Creating an Instance

First off, in your javascript file, define Weblgcy:

```js
const Weblgcy = require('weblgcy')
```
FullHost defines fullNode and solidityNode while the eventServer is specified, and the privateKey is passed separately.

```js
const weblgcy = new Weblgcy({
    fullNode: 'http://<ip>:<portnumber>',
    solidityNode: 'http://<ip>:<portnumber>'
    eventServer: 'http://<ip>:<portnumber>',
    privateKey: '...'
  }
)
```

## Contributions

In order to contribute you can

* fork this repo and clone it locally
* install the dependencies — `npm i`
* do your changes to the code
* build the Weblgcy dist files — `npm run build`
