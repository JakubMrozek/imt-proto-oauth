'use strict'

const request = require('request');

const TOKENS = new Map();

/**
 * Save token to local memory store. This method is overriden by different store logic on production servers.
 *
 * @param {String} id Token.
 * @param {Object} data Data to be stored with token.
 * @param {Function} callback Callback.
 */

IMTOAuthAccount.createToken = function createToken(id, data, done) {
	if (TOKENS.has(id))
		return setImmediate(() => done(new Error("Token already exists.")));
	
	TOKENS.set(id, data);
	
	setImmediate(() => done(null));
}

/**
 * Delete token from local memory store. This method is overriden by different store logic on production servers.
 *
 * @param {String} id Token.
 */

IMTOAuthAccount.deleteToken = function deleteToken(id) {
	TOKENS.delete(id);
}

/**
 * Get token from local memory store. This method is overriden by different store logic on production servers.
 *
 * @param {String} id Token.
 * @param {Function} callback Callback.
 */

IMTOAuthAccount.getToken = function getToken(id, done) {
	if (!TOKENS.has(id))
		return setImmediate(() => done(new Error("Token doesn't exists.")));
	
	setImmediate(() => done(null, TOKENS.get(id)));
}

Object.assign(IMTOAuthAccount.prototype, {
	/**
	 *
	 */
	
	accountFromCallbackRequest(request, done) {
		let rt = this.getTokenFromRequest(request);
		
		IMTOAuthAccount.getToken(rt, (err, token) => {
			if (err) return done(err);
			
			this.id = token.account;
			this.acceptedScope = token.scope;

			IMTOAuthAccount.deleteToken(rt);

			done(null);
		});
	},
	
	/**
	 *
	 */

	extendScope(scope, done) {
		this.authorize(scope, done);
	},
	
	/**
	 *
	 */
	
	reauthorize(done) {
		this.authorize(this.scope, done);
	},
	
	/**
	 *
	 */
	
	saveExpire(body) {
		if (body != null && body.expires_in != null) {
			let date = new Date(this.environment.currentDate.getTime());
			date.setSeconds(date.getSeconds() + body.expires_in);
			this.data.expire = date;
		}
	},

	/**
	 *
	 */
	
	invalidate(done) {
		this.post(this.options.invalidateUri, null, done);
	},
	
	/**
	 *
	 */
	
	getUserInfo(done) {
		this.get(this.options.infoUri, done);
	},
	
	/**
	 *
	 */
	
	saveMetadata(response, body) {
		/*this.uid = value;
		this.metadata = {
			value: value,
			type: 'type'
		}*/
	},
	
	/**
	 *
	 */
	
	query(options, done) {
		request(options, done);
	}
})
