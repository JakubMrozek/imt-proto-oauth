'use strict'

const OAuth2Client = require('../lib-es6/oauth2_client.js');
const nock = require('nock');

describe('OAuth2', () => {
	describe('Parts', () => {
		let oauth;
		
		before(() => {
			oauth = new OAuth2Client({
				clientId: 'APP_KEY',
				clientSecret: 'APP_SECRET',
				authorizeUri: 'https://example.com/authorize',
				tokenUri: 'https://example.com/access_token',
				redirectUri: 'https://example.com/aouth/'
			});
		});

		it('Generate authorize url - object', (done) => {
			let url = oauth.getAuthorizeUrl({ a: 1, b: 2 });
			url.should.match(/https:\/\/example\.com\/authorize\?a=1&b=2&client_id=APP_KEY/);
			done();
		});

		it('Generate authorize url - scopes', (done) => {
			let url = oauth.getAuthorizeUrl(['a', 'b', 'c']);
			url.should.match(/https:\/\/example\.com\/authorize\?response_type=code&client_id=APP_KEY&redirect_uri=https%3A%2F%2Fexample\.com%2Faouth%2F&state=[^&]{20}&scope=a%2Cb%2Cc/);
			done();
		});
	});

	describe('GitHub flow', () => {
		let oauth;
		
		before(() => {
			oauth = new OAuth2Client({
				clientId: 'APP_KEY',
				clientSecret: 'APP_SECRET',
				authorizeUri: 'https://github.com/login/oauth/authorize',
				tokenUri: 'https://github.com/login/oauth/access_token',
				redirectUri: 'https://www.integromat.com/aouth/cb/github'
			});
		});


		it('Generate authorize url', (done) => {
			oauth.setScopeSeparator(' ');
			oauth.getAuthorizeUrl(['user']).should.match(/https:\/\/github.com\/login\/oauth\/authorize\?response_type=code&client_id=APP_KEY&redirect_uri=https%3A%2F%2Fwww\.integromat\.com%2Faouth%2Fcb%2Fgithub&state=[^&]{20}&scope=user/);
			done();
		});

		it('Get access token - pass', (done) => {
			nock('https://github.com')
			.post('/login/oauth/access_token')
			.reply(200, {
				access_token: 'ACCESS_TOKEN',
				token_type: 'bearer',
				scope: 'user'
			});

			oauth.getAccessToken({
				client_secret: this.clientSecret,
				code: 'CODE',
				redirect_uri: this.redirectUri
			}, (err, res, body) => {
				res.statusCode.should.equal(200);
				res.body.should.eql({
					access_token: 'ACCESS_TOKEN',
					token_type: 'bearer',
					scope: 'user'
				});
				done();
			});
		});

		it('Get access token - fail, expired code', (done) => {
			nock('https://github.com')
			.post('/login/oauth/access_token')
			.reply(200, {
				error: 'bad_verification_code',
				error_description: 'The code passed is incorrect or expired.',
				error_uri: 'https://developer.github.com/v3/oauth/#bad-verification-code'
			});

			oauth.getAccessToken({
				client_secret: oauth.clientSecret,
				code: 'CODE',
				redirect_uri: 'https://www.integromat.com/oauth/cb/github'
			}, (err, res, body) => {
				res.statusCode.should.equal(200);
				res.body.should.eql({
					error: 'bad_verification_code',
					error_description: 'The code passed is incorrect or expired.',
					error_uri: 'https://developer.github.com/v3/oauth/#bad-verification-code'
				});
				done();
			});
		});
	});

	describe('Asana flow', () => {
		let oauth;
		
		before(() => {
			oauth = new OAuth2Client({
				clientId: 'APP_KEY',
				clientSecret: 'APP_SECRET',
				authorizeUri: 'https://app.asana.com/-/oauth_authorize',
				tokenUri: 'https://app.asana.com/-/oauth_token',
				redirectUri: 'https://www.integromat.com/oauth/cb/asana/'
			});
		});


		it('Generate authorize url', (done) => {
			oauth.getAuthorizeUrl().should.match(/https:\/\/app\.asana.com\/-\/oauth_authorize\?response_type=code&client_id=APP_KEY&redirect_uri=https%3A%2F%2Fwww\.integromat\.com%2Foauth%2Fcb%2Fasana%2F&state=[^&]{20}/);
			done();
		});


		it('Get access token - pass', (done) => {
			nock('https://app.asana.com')
			.post('/-/oauth_token')
			.reply(200, {
				access_token: 'ACCESS_TOKEN',
				token_type: 'bearer',
				expires_in: 3600,
				data: {
					id: 123456,
					name: 'Integromat',
					email: 'email@example.com'
				},
				refresh_token: 'REFRESH_TOKEN'
			});

			oauth.getAccessToken('REFRESH_TOKEN', (err, res, body) => {
				res.statusCode.should.equal(200);
				res.body.should.eql({
					access_token: 'ACCESS_TOKEN',
					token_type: 'bearer',
					expires_in: 3600,
					data: {
						id: 123456,
						name: 'Integromat',
						email: 'email@example.com'
					},
					refresh_token: 'REFRESH_TOKEN'
				});
				done();
			});
		});

		it('Get refresh token - pass', (done) => {
			nock('https://app.asana.com')
			.post('/-/oauth_token')
			.reply(200,{
				access_token: 'ACCESS_TOKEN',
				token_type: 'bearer',
				expires_in: 3600,
				data: {
					id: 123456,
					name: 'Integromat',
					email: 'email@example.com'
				}
			});

			oauth.getRefreshToken('REFRESH_TOKEN' , (err, res, body) => {
				res.statusCode.should.equal(200);
				res.body.access_token.should.equal('ACCESS_TOKEN');
				done();
			});
		});


		it('Make secure request - get user info', (done) => {
			nock('https://app.asana.com')
			.get('/api/1.0/users/me')
			.reply(200,{
				data: {
					id: 123456,
					name: 'Integromat',
					email: 'email@example.com'
				}
			});

			oauth.get('https://app.asana.com/api/1.0/users/me', 'ACCESS_TOKEN', (err, res, body) => {
				body.data.id.should.equal(123456);

				done();
			});
		});

	});
});
