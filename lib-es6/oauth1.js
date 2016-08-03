'use strict'

const debug = require('debug')('imt:proto:oauth1');

global.IMTOAuth1Account = class IMTOAuth1Account extends IMTOAuthAccount {
	/**
	 *
	 */
	
	constructor(options) {
		super();
		
		this.options = options || {};
		this.options.version = this.options.version || '1.0A';
	}

	/**
	 *
	 */
	
	initialize(done) {
		this.options.clientId = this.data.consumerKey || this.common.consumerKey;
		this.options.clientSecret = this.data.consumerSecret || this.common.consumerSecret;
		this.options.redirectUri = this.options.redirectUri || `https://${this.environment.host}/oauth/cb/${this.name}/`;
		
		let oauth = require('oauth');
		this.client = new oauth.OAuth(this.options.requestUri, this.options.tokenUri, this.options.clientId, this.options.clientSecret, this.options.version, this.options.redirectUri, 'HMAC-SHA1');
		
		done();
	}

	/**
	 *
	 */
	
	authorize(scope, done) {
		this.client.getOAuthRequestToken((err, oauthToken, oauthTokenSecret) => {
			let error = this.getResponseError(err);
			if (error) return done(error);
			
			this.data.requestToken = oauthToken;
			this.data.requestTokenSecret = oauthTokenSecret;
			
			IMTOAuthAccount.createToken(oauthToken, {
				account: this.id,
				expires: this.environment.currentDate.getTime() + (900 * 1000) // 15 minutes
			}, (err) => {
				if (err) return done(err);
				
				done(null, this.getAuthorizeUrl(oauthToken));
			});
		});
	}

	/**
	 *
	 */
	
	callback(request, done) {
		if (this.isAccessDenied(request)) return done(new Error('Access Denied.'));

		this.client.getOAuthAccessToken(this.data.requestToken, this.data.requestTokenSecret, request.query.oauth_verifier, (err, accessToken, accessTokenSecret, data) => {
			let error = this.getResponseError(err);
			if (error) return done(error);
			
			delete this.data.requestToken;
			delete this.data.requestTokenSecret;
			
			this.saveTokens(accessToken, accessTokenSecret, data);
			this.saveExpire(data);
			done(null);
		});
	}

	/**
	 *
	 */
	
	test(done) {
		this.getUserInfo((err, response, body) => {
			if (err) return done(err, false);

			this.saveMetadata(response, body);
			
			done(null, true);
		});
	}

	/**
	 *
	 */
	
	get(url, done) {
		if (!this.data.accessToken) return done(new Error('No access token specified.'));

		this.client.get(url, this.data.accessToken, this.data.accessTokenSecret, (err, data, response) => {
			let error = this.getResponseError(err);
			if (error) return done(error);
			
			if (/^application\/json/.test(response.headers['content-type'])) {
				try {
					var body = JSON.parse(data);
				} catch (e) {
					return done(new Error('Invalid response JSON.'));
				}
			} else {
				return done(new Error('Invalid response type.'));
			}
			
			done(null, response, body);
		});
	}

	/**
	 *
	 */
	
	getAuthorizeUrl(token) {
		return `${this.options.authorizeUri}?oauth_token=${token}`;
	}

	/**
	 *
	 */
	
	getTokenFromRequest(request) {
		return request.query.oauth_token || request.query.denied;
	}

	/**
	 *
	 */
	
	isAccessDenied(request) {
		return request.query.denied;
	}

	/**
	 *
	 */
	
	saveTokens(accessToken, accessTokenSecret, data) {
		this.data.accessToken = accessToken;
		this.data.accessTokenSecret = accessTokenSecret;
	}

	/**
	 *
	 */
	
	getResponseError(err) {
		if (!err) return false;
		if (err instanceof Error) return err;
		if (err.statusCode && err.statusCode < 300) return false;
		return new Error(err.data);
	}
}
