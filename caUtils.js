"use strict"
const FabricCAServices=require('fabric-ca-client')
const adminCreds=require("./adminCreds.json")
const{buildCCPOrg, buildWallet, getMSPId}=require("./util.js")
const{}=require("./util.js")
/**
 *
 * @param {*} FabricCAServices
 * @param {*} ccp
 */
exports.buildCAClient = (orgId) => {
	// Create a new CA client for interacting with the CA.
    const ccp = buildCCPOrg(orgId)
	const caInfo = ccp.certificateAuthorities[`ca.${orgId.toLowerCase()}.example.com`]; //lookup CA details from config
	const caTLSCACerts = caInfo.tlsCACerts.pem;
	const caClient = new FabricCAServices(caInfo.url, { trustedRoots: caTLSCACerts, verify: false }, caInfo.caName);

	console.log(`Built a CA Client named ${caInfo.caName}`);
	return caClient;
};


console.log

exports.enrollAdmin = async function (orgId) {
	try {

        const ccClient = module.exports.buildCAClient(orgId)

        const wallet = await buildWallet()
		// Check to see if we've already enrolled the admin user.
		const orgMspId = getMSPId(orgId)

		const identity = await wallet.get(adminUserId);
		if (identity) {
			console.log('An identity for the admin user already exists in the wallet');
			return;
		}

		// Enroll the admin user, and import the new identity into the wallet.
		const enrollment = await caClient.enroll({ enrollmentID: adminCreds.userId, enrollmentSecret: adminCreds.password });
		const x509Identity = {
			credentials: {
				certificate: enrollment.certificate,
				privateKey: enrollment.key.toBytes(),
			},
			mspId: orgMspId,
			type: 'X.509',
		};
		await wallet.put(adminCreds.userId, x509Identity);
		console.log('Successfully enrolled admin user and imported it into the wallet');
	} catch (error) {
		console.error(`Failed to enroll admin user : ${error}`);
	}
};

/**
 * Registering the new identity based on the role
 * @param {String} orgId 
 * @param {String} userId 
 * @param {String} role 
 * @returns 
 */


exports.registerAndEnrollUser = async (orgId, userId, role) => {
	try {


		// Building a CA Client
        const caClient = module.exports.buildCAClient(orgId)

		// Retirving the wallet object
        const wallet = await buildWallet()
        const orgMspId = getMSPId(orgId)
        
		// Check to see if we've already enrolled the user
		const userIdentity = await wallet.get(userId);
		if (userIdentity) {
			console.log(`An identity for the user ${userId} already exists in the wallet`);
			return;
		}

		// Must use an admin to register a new user
		const adminIdentity = await wallet.get(adminCreds.userId);
		if (!adminIdentity) {
			console.log('An identity for the admin user does not exist in the wallet');
			console.log('Enroll the admin user before retrying');
			return;
		}

		// build a user object for authenticating with the CA
		const provider = wallet.getProviderRegistry().getProvider(adminIdentity.type);
		const adminUser = await provider.getUserContext(adminIdentity, adminCreds.userId);

		// Register the user, enroll the user, and import the new identity into the wallet.
		// if affiliation is specified by client, the affiliation value must be configured in CA
		const secret = await caClient.register({
			affiliation: `${orgId.toLowerCase()}.department1`,
			enrollmentID: userId,
			role: role
		}, adminUser);

        // Enrolling the identity    
		const enrollment = await caClient.enroll({
			enrollmentID: userId,
			enrollmentSecret: secret
		});

		// Creating a JSON object for the identity
		const x509Identity = {
			credentials: {
				certificate: enrollment.certificate,
				privateKey: enrollment.key.toBytes(),
			},
			mspId: orgMspId,
			type: 'X.509',
		};


		// Stroing the identity in the wallet
		await wallet.put(userId, x509Identity);

		return x509Identity;
	} catch (error) {

		// Returing if the error occurs
		console.error(`Failed to register user : ${error}`);
		return error
	}
};

module.exports.registerAndEnrollUser('org1', 'user1', 'client').then(console.log)

console.log(module.exports.buildCAClient("Org1"))
