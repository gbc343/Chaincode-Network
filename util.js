const fs = require('fs');
const path = require('path');
const {Wallets}=require("fabric-network")


/**
 * Function returns the path for Filestystem Wallet
 * @returns {String}
 * 
 */
function getWalletPath(){
  return path.resolve(__dirname, "wallet");
}



/**
 * Function returns the ccp object for the org
 * @param {String} orgName 
 * @returns  {JSON}
 */
exports.buildCCPOrg = (orgName) => {
	// load the common connection configuration file
	const ccpPath = path.resolve(__dirname, 'connections',  `connection-${orgName.toLowerCase()}.json`);
	const fileExists = fs.existsSync(ccpPath);
	if (!fileExists) {
		throw new Error(`no such file or directory: ${ccpPath}`);
	}
	const contents = fs.readFileSync(ccpPath, 'utf8');

	// build a JSON object from the file contents
	const ccp = JSON.parse(contents);

	console.log(`Loaded the network configuration located at ${ccpPath}`);
	return ccp;
};

/**
 * Function returns the wallet object. 
 * If the walletpath does not exists on the local filesystem
 * a In-Memory wallet is returned
 * @returns {Object}
 */
exports.buildWallet = async () => {
	// Create a new  wallet : Note that wallet is for managing identities.
	let wallet;
    const walletPath = getWalletPath();

	// Checking if the wallet directory exists
	if (fs.existsSync(walletPath)) {
        
		// If the directory exists a FileSystem wallet is created
		wallet = await Wallets.newFileSystemWallet(walletPath);
		console.log(`Built a file system wallet at ${walletPath}`);
	} else {

		// If not the In-Memory wallet is created
		wallet = await Wallets.newInMemoryWallet();
		console.log('Built an in memory wallet');
	}

	return wallet;
};


/**
 * The function stringifies the JSON object
 * @param {String} inputString 
 * @returns {String} 
 */
exports.prettyJSONString = (inputString) => {
	if (inputString) {
		 return JSON.stringify(JSON.parse(inputString), null, 2);
	}
	else {
		 return inputString;
	}
}




exports.getMSPId=function(orgId){
     return `${orgId.charAt(0).toUpperCase()}${orgId.slice(1)}MSP`;
}