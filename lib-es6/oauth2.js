'use strict'

const Client = require('./oauth2_client');
const debug = require('debug')('imt:proto:oauth2');

global.IMTOAuth2Account = class IMTOAuth2Account extends IMTOAuthAccount {
	/**
	 *
	 */

	constructor(options) {
		super();

		this.options = options || {};
	}

	/**
	 *
	 */

	initialize(done) {
		this.options.clientId = this.data.consumerKey || this.common.consumerKey;
		this.options.clientSecret = this.data.consumerSecret || this.common.consumerSecret;
		this.options.redirectUri = this.options.redirectUri || `https://${this.environment.host}/oauth/cb/${this.name}`;

		this.client = new Client(this.options)
		done();
	}

	/**
	 *
	 */

	authorize(scope, done) {
		let params = {
			redirect_uri: this.options.redirectUri,
			state: this.client.state,
			client_id: this.options.clientId,
			response_type: 'code'
		}

		scope = this.scope.concat(scope);
		if (scope.length) params.scope = scope.join(this.options.scopeSeparator);

		if (this.options.authorizeParams) Object.assign(params, this.options.authorizeParams);

		IMTOAuthAccount.createToken(params.state, {
			account: this.id,
			scope,
			expires: this.environment.currentDate.getTime() + (900 * 1000) // 15 minutes
		}, (err) => {
			if (err) return done(err);

			done(null, this.client.getAuthorizeUrl(params));
		});
	}

	/**
	 *
	 */

	callback(request, done) {
		if (this.isAccessDenied(request)) return done(new Error('Access Denied.'));

		let params = {
			code: request.query.code,
			redirect_uri: this.options.redirectUri,
			grant_type: 'authorization_code'
		};

		params.code = request.query.code;
		this.client.getAccessToken(params, (err, response, body) => {
			let error = this.getResponseError(err, response);
			if (error) return done(error);

			if ('string' === typeof body) {
				body = require('querystring').parse(body);
			}

			this.saveTokens(body);
			this.saveExpire(body);
			this.saveScope(body, done);
		})
	}

	/**
	 *
	 */

	test(done) {
		this.refreshToken(err => {
			if (err) return done(err, false);

			this.getUserInfo((err, response, body) => {
				if (err) return done(err, false);

				this.saveMetadata(response, body);

				done(null, true);
			});
		});
	}

	/**
	 *
	 */

	getTokenFromRequest(request) {
		return request.query.state;
	}

	/**
	 *
	 */

	isAccessDenied(request) {
		return request.query.error && request.query.error === 'access_denied';
	}

	/**
	 *
	 */

	saveTokens(body) {
		this.data.accessToken = body.access_token;
		if (body.refresh_token) this.data.refreshToken = body.refresh_token;
	}

	/**
	 *
	 */

	get(url, done) {
		if (!this.data.accessToken) return done(new Error('No access token specified.'));

		this.client.get(url, this.data.accessToken, (err, response, body) => {
			let error = this.getResponseError(err, response);
			if (error) return done(error);

			done(null, response, body);
		});
	}

	/**
	 *
	 */

	post(url, body, done) {
		if (!this.data.accessToken) return done(new Error('No access token specified.'));

		if (body) body = JSON.stringify(body);
		let accessToken = this.data.accessToken;
		let headers = {};

		this.client.post(url, accessToken, (err, response, body) => {
			let error = this.getResponseError(err, response);
			if (error) return done(error);

			done(null, response, body);
		});
	}

	/**
	 *
	 */

	refreshToken(done) {
		if (!this.options.refreshToken) return done();
		if (!this.data.refreshToken) return done(new Error('No refresh token specified.'));

		let params = {
			grant_type: 'refresh_token',
			refresh_token: this.data.refreshToken
		};

		this.client.getRefreshToken(params, (err, reponse, body) => {
			let error = this.getResponseError(err);
			if (error) return done(error);

			this.saveTokens(body);

			done(null, body);
		});
	}

	/**
	 *
	 */

	validateWithRefreshToken(done) {
		if (this.data.expire) this.data.expire = new Date(this.data.expire);
		if (this.data.expire && (this.data.expire.getTime() - this.scenario.timeout > this.environment.currentDate.getTime())) {
			return done(null, false);
		}

		this.options.refreshToken = true;
		this.refreshToken((err, body) => {
			if (err) return done(err);

			this.saveExpire(body);

			done(null, true);
		});
	}

	/**
	 *
	 */

	getResponseError(err, response) {
		if (!err && response.statusCode < 300) return false;
		if (err instanceof Error) return err
		return new Error(response.body);
	}
}
