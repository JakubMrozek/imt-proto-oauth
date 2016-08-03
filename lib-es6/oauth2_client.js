'use strict'

const request = require('request');
const crypto = require('crypto');
const qs = require('qs');

class OAuth2Client {
	constructor (options){
		if (typeof options !== 'object') {
			throw new Error('Undefined is not a valid options object.');
		}

		this.clientId = options.clientId;
		this.clientSecret = options.clientSecret;
		this.authorizeUri = options.authorizeUri;
		this.tokenUri = options.tokenUri;
		this.redirectUri = options.redirectUri;
		this.customHeaders = options.customHeaders || {};
		this.accessTokenType = options.accessTokenType || 'Bearer';
		this.scopeSeparator = options.scopeSeparator || ',';
		this.useAuthHeader = options.useAuthHeader || true;
		this.useState = options.useState || true;
		
		if (this.useState) this.state = crypto.randomBytes(10).toString('hex');
	}

	setAccessTokenName (name){
		this.accessTokenName = name;
	}

	setAccessTokenType (type){
		this.accessTokenType = type;
	}

	setScopeSeparator (separator){
		this.scopeSeparator = separator;
	}

	useAuthHeader (use){
		this.useAuthHeader = options.useAuthHeader;
	}

	_buildAuthHeader (token) {
		return `${this.accessTokenType} ${token}`;
	}

	_getDefaultAuthorizeParameters (){
		let params = {
			response_type: 'code',
			client_id: this.clientId,
			redirect_uri: this.redirectUri
		};
		
		if (this.useState) params.state = this.state;
		
		return params;
	}

	_getDefaultAccessTokenParameters (code){
		return {
			grant_type: 'authorization_code',
			code,
			redirect_uri: this.redirectUri,
			client_id: this.clientId,
			client_secret: this.clientSecret
		};
	}

	_getDefaultRefreshTokenParameters (refreshToken){
		return {
			grant_type: 'refresh_token',
			refresh_token: refreshToken,
			client_id: this.clientId,
			client_secret: this.clientSecret
		};
	}

	getAuthorizeUrl (scope){
		scope = scope || [];
		
		if (Array.isArray(scope)){
			let query = this._getDefaultAuthorizeParameters();

			if (scope.length > 0)
				query.scope = scope.join(this.scopeSeparator);

			return `${this.authorizeUri}?${qs.stringify(query)}`;

		}
		scope.client_id = this.clientId;
		return `${this.authorizeUri}?${qs.stringify(scope)}`;
	}

	_request (params, done){
		request({
			uri: this.tokenUri,
			method: 'POST',
			json: true,
			form: params,
			headers: this.customHeaders
		},
		done);
	}

	getAccessToken (code, done){
		if (typeof code === 'object'){
			code.client_id = this.clientId;
			code.client_secret = this.clientSecret;
			return this._request(code, done);
		}
		return this._request(this._getDefaultAccessTokenParameters(code), done);
	}

	getRefreshToken (refreshToken, done){
		if (typeof refreshToken === 'object') {
			refreshToken.client_id = this.clientId;
			refreshToken.client_secret = this.clientSecret;
			return this._request(refreshToken, done);
		}
		return this._request(this._getDefaultRefreshTokenParameters(refreshToken), done);
	}

	_secureRequest (method, accessToken){
		return request.defaults({
			method: method,
			json: true,
			headers: { 'Authorization': this._buildAuthHeader(accessToken) }
		});
	}


	get (options, accessToken, done){ this._secureRequest('GET', accessToken)(options, done); }
	post (options, accessToken, done){ this._secureRequest('POST', accessToken)(options, done); }
}


module.exports = OAuth2Client;
