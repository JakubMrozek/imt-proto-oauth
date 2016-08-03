'use strict'

if (!global.IMT_PROTO_LOADED) {
	console.error('Dependency imt-proto is not loaded.');
	process.exit(1);
}

if (global.IMT_PROTO_OAUTH_LOADED) return;
global.IMT_PROTO_OAUTH_LOADED = true;

require('./lib-es6/oauth.js');
require('./lib-es6/oauth1.js');
require('./lib-es6/oauth2.js');
