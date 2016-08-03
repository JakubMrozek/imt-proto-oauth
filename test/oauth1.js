'use strict'

const assert = require('assert');
const nock = require('nock');

const COMMON = {consumerKey: 'APP_KEY', consumerSecret: 'APP_SECRET'};
const ENVIRONMENT = {host: 'www.integromat.com', currentDate: new Date()};

class TestAccount extends IMTOAuth1Account {
	constructor() {
		super({
			authorizeUri: 'https://twitter.com/oauth/authorize',
			requestUri: 'https://api.twitter.com/oauth/request_token',
			tokenUri: 'https://api.twitter.com/oauth/access_token',
			infoUri: 'https://api.twitter.com/1.1/account/verify_credentials.json'
		})
	}

	saveMetadata(res, body) {
		this.uid = body ? body.id_str : null
		
		if (body && body.name) {
			this.metadata = {
				value: body.name,
				type: 'text'
			}
		}
	}
}

nock.disableNetConnect();

describe('IMTOAuth1Account', () => {
	let DATA = {}; // Persistent storage
	
	it('should create authorization url', (done) => {
		nock('https://api.twitter.com:443')
		.post('/oauth/request_token')
		.reply(200, "oauth_token=REQUEST_TOKEN&oauth_token_secret=REQUEST_TOKEN_SECRET&oauth_callback_confirmed=true");
		
		let account = new TestAccount();
		account.id = 1;
		account.name = 'twitter';
		account.data = DATA;
		account.common = COMMON;
		account.environment = ENVIRONMENT;
		account.initialize((err) => {
			if (err) return done(err);
			
			account.authorize([], (err, url) => {
				if (err) return done(err);
				
				assert.strictEqual(url, 'https://twitter.com/oauth/authorize?oauth_token=REQUEST_TOKEN')

				assert.ok(account instanceof IMTOAuth1Account);
				assert.ok(account instanceof IMTOAuthAccount);
				assert.ok(account instanceof IMTAccount);

				let token = require('querystring').parse(require('url').parse(url).query).oauth_token;
				IMTOAuthAccount.getToken(token, (err, data) => {
					if (err) return done(err);
					
					assert.strictEqual(data.account, 1);
					assert.strictEqual(data.scope, undefined);
					assert.strictEqual(DATA.requestToken, 'REQUEST_TOKEN');
					assert.strictEqual(DATA.requestTokenSecret, 'REQUEST_TOKEN_SECRET');

					account.finalize(done)
				})
			})
		})
	})
	
	it('should process callback', (done) => {
		nock('https://api.twitter.com:443')
		.post('/oauth/access_token')
		.reply(200, "oauth_token=ACCESS_TOKEN&oauth_token_secret=ACCESS_TOKEN_SECRET&user_id=132244556&screen_name=patriksimek&x_auth_expires=0");
		
		let request = {
			query: {
				oauth_token: 'REQUEST_TOKEN',
				oauth_verifier: 'REQUEST_VERIFIER'
			}
		}

		let account = new TestAccount();
		account.accountFromCallbackRequest(request, (err) => {
			assert.strictEqual(account.id, 1);

			account.name = 'twitter';
			account.data = DATA;
			account.common = COMMON;
			account.environment = ENVIRONMENT;
			account.initialize((err) => {
				if (err) return done(err);
				
				account.callback(request, (err) => {
					if (err) return done(err);
					
					assert.strictEqual(DATA.accessToken, 'ACCESS_TOKEN');
					assert.strictEqual(DATA.accessTokenSecret, 'ACCESS_TOKEN_SECRET');
	
					account.finalize(done)
				})
			})
		})
	})
	
	it('should test account', (done) => {
		nock('https://api.twitter.com:443')
		.get('/1.1/account/verify_credentials.json')
		.reply(200, {
		   "id_str" : "132244556",
		   "name" : "Patrik Šimek"
		});
		
		let account = new TestAccount();
		account.id = 1;
		account.name = 'twitter';
		account.data = DATA;
		account.common = COMMON;
		account.environment = ENVIRONMENT;
		account.initialize((err) => {
			if (err) return done(err);
			
			account.test((err) => {
				if (err) return done(err);
				
				assert.strictEqual(account.uid, '132244556');
				assert.deepStrictEqual(account.metadata, {
					value: 'Patrik Šimek',
					type: 'text'
				});

				account.finalize(done)
			})
		})
	})
});

