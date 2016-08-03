'use strict'

const assert = require('assert');
const nock = require('nock');

const COMMON = {consumerKey: 'APP_KEY', consumerSecret: 'APP_SECRET'};
const ENVIRONMENT = {host: 'www.integromat.com', currentDate: new Date()};

class TestAccount extends IMTOAuth2Account {
	constructor() {
		super({
			authorizeUri: 'https://www.facebook.com/dialog/oauth',
			tokenUri: 'https://graph.facebook.com/oauth/access_token',
			infoUri: 'https://graph.facebook.com/me',
			useState: true,
			authorizeParams: {
				display: 'popup'
			}
		});
	}

	saveExpire(body) {
		let date = new Date();
		date.setDate(date.getDate() + 60);
		this.expire = date;
	}

	saveScope(body, done) {
		this.get('https://graph.facebook.com/v2.3/me/permissions', (err, response, body) => {
			if (err) return done(err);
			
			for (let i = 0; i < body.data.length; i++) {
				let s = body.data[i];
				if (s.status === 'granted' && this.scope.indexOf(s.permission) === -1) {
					this.scope.push(s.permission);
				}
			}
			
			done();
		});
	}

	saveMetadata(response, body) {
		this.uid = body ? body.id : null
		
		if (body && body.name) {
			this.metadata = {
				value: body.name,
				type: 'text'
			}
		}
	}

	getResponseError(err, response) {
		if (!err && response.statusCode < 300) return false;
		if (err instanceof Error) return err
		
		err = response.body.error;
		return new Error(err.message);
	}
}

nock.disableNetConnect();

describe('IMTOAuth2Account', () => {
	let DATA = {}; // Persistent storage
	let SCOPE = []; // Persistent storage

	it('should create authorization url', (done) => {
		let account = new TestAccount();
		account.id = 1;
		account.name = 'facebook';
		account.data = DATA;
		account.scope = SCOPE;
		account.common = COMMON;
		account.environment = ENVIRONMENT;
		account.initialize((err) => {
			if (err) return done(err);
			
			account.client.state = 'STATE'; // Just for testing purposes.
			
			account.authorize([], (err, url) => {
				if (err) return done(err);
				
				assert.strictEqual(url, 'https://www.facebook.com/dialog/oauth?redirect_uri=https%3A%2F%2Fwww.integromat.com%2Foauth%2Fcb%2Ffacebook&state=STATE&client_id=APP_KEY&response_type=code&display=popup');

				assert.ok(account instanceof IMTOAuth2Account);
				assert.ok(account instanceof IMTOAuthAccount);
				assert.ok(account instanceof IMTAccount);

				let token = require('querystring').parse(require('url').parse(url).query).state;
				IMTOAuthAccount.getToken(token, (err, data) => {
					if (err) return done(err);

					assert.strictEqual(data.account, 1);
					assert.deepStrictEqual(data.scope, []);

					account.finalize(done)
				})
			})
		})
	})

	it('should process callback', (done) => {
		nock('https://graph.facebook.com:443')
		.post('/oauth/access_token', "code=CODE&redirect_uri=https%3A%2F%2Fwww.integromat.com%2Foauth%2Fcb%2Ffacebook&grant_type=authorization_code&client_id=APP_KEY&client_secret=APP_SECRET")
		.reply(200, "access_token=ACCESS_TOKEN&expires=5179716");
	
		nock('https://graph.facebook.com:443')
		.get('/v2.3/me/permissions')
		.query({"access_token":"ACCESS_TOKEN"})
		.reply(200, {"data":[{"permission":"public_profile","status":"granted"}]});
		
		let request = {
			query: {
				code: 'CODE',
				state: 'STATE'
			}
		}

		let account = new TestAccount();
		account.name = 'facebook';
		account.data = DATA;
		account.scope = SCOPE;
		account.common = COMMON;
		account.environment = ENVIRONMENT;
		account.initialize((err) => {
			if (err) return done(err);
			
			account.callback(request, (err) => {
				if (err) return done(err);

				assert.deepStrictEqual(SCOPE, ['public_profile']);
				assert.strictEqual(DATA.accessToken, 'ACCESS_TOKEN');

				account.finalize(done)
			})
		})
	})
	
	it('should test account', (done) => {
		nock('https://graph.facebook.com:443')
		.get('/me')
		.query({"access_token":"ACCESS_TOKEN"})
		.reply(200, {"id":"10205323400763280","first_name":"Patrik","gender":"male","last_name":"Šimek","link":"https://www.facebook.com/app_scoped_user_id/10205323400763280/","locale":"cs_CZ","name":"Patrik Šimek","timezone":2,"updated_time":"2016-06-08T22:00:07+0000","verified":true});
		
		//DATA = {accessToken: 'ACCESS_TOKEN'};
		
		let account = new TestAccount();
		account.id = 1;
		account.name = 'facebook';
		account.data = DATA;
		account.scope = SCOPE;
		account.common = COMMON;
		account.environment = ENVIRONMENT;
		account.initialize((err) => {
			if (err) return done(err);
			
			account.test((err) => {
				if (err) return done(err);

				assert.strictEqual(account.uid, '10205323400763280');
				assert.deepStrictEqual(account.metadata, {
					value: 'Patrik Šimek',
					type: 'text'
				});

				account.finalize(done)
			})
		})
	})
	
	it('should create extension url', (done) => {
		DATA = {accessToken: 'ACCESS_TOKEN'};
		
		let account = new TestAccount();
		account.generateState = (done) => done(null, 'STATE'); // Just for testing purposes.
		account.id = 1;
		account.name = 'facebook';
		account.data = DATA;
		account.scope = SCOPE;
		account.common = COMMON;
		account.environment = ENVIRONMENT;
		account.initialize((err) => {
			if (err) return done(err);
			
			account.client.state = 'STATE'; // Just for testing purposes.
			
			account.extendScope(['user_photos', 'user_videos'], (err, url) => {
				if (err) return done(err);

				assert.strictEqual(url, 'https://www.facebook.com/dialog/oauth?redirect_uri=https%3A%2F%2Fwww.integromat.com%2Foauth%2Fcb%2Ffacebook&state=STATE&client_id=APP_KEY&response_type=code&scope=public_profile%2Cuser_photos%2Cuser_videos&display=popup');

				account.finalize(done)
			})
		})
	})

	it('should process extension callback', (done) => {
		nock('https://graph.facebook.com:443')
		.post('/oauth/access_token', "code=CODE&redirect_uri=https%3A%2F%2Fwww.integromat.com%2Foauth%2Fcb%2Ffacebook&grant_type=authorization_code&client_id=APP_KEY&client_secret=APP_SECRET")
		.reply(200, "access_token=ACCESS_TOKEN&expires=5177478");
	
		nock('https://graph.facebook.com:443')
		.get('/v2.3/me/permissions')
		.query({"access_token":"ACCESS_TOKEN"})
		.reply(200, {"data":[{"permission":"user_photos","status":"granted"},{"permission":"user_videos","status":"granted"},{"permission":"public_profile","status":"granted"}]});
		
		let request = {
			query: {
				code: 'CODE',
				state: 'STATE'
			}
		}

		let account = new TestAccount();
		account.name = 'facebook';
		account.data = DATA;
		account.scope = SCOPE;
		account.common = COMMON;
		account.environment = ENVIRONMENT;
		account.initialize((err) => {
			if (err) return done(err);
			
			account.callback(request, (err) => {
				if (err) return done(err);

				assert.deepStrictEqual(SCOPE, ['public_profile', 'user_photos', 'user_videos']);
				assert.strictEqual(DATA.accessToken, 'ACCESS_TOKEN');
				
				account.finalize(done)
			})
		})
	})
});

