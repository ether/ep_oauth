'use strict';

const db = require('ep_etherpad-lite/node/db/DB').db;
const settings = require('ep_etherpad-lite/node/utils/Settings');
const request = require('request');

// Below two lines are not used yet but probably will be at some point
/* eslint-disable-next-line node/no-unpublished-require */
const OAuth2 = require('oauth').OAuth2;

// Setup the oauth2 connector -- Doesn't establish any connections etc.
const oauth2 = new OAuth2(settings.ep_oauth.clientID,
    settings.ep_oauth.clientSecret,
    'https://github.com/',
    'login/oauth/authorize',
    'login/oauth/access_token',
    null); /** Custom headers */

exports.expressConfigure = (hookName, args, cb) => {
  // args.app.get('/auth/callback', function(req, res){

  // THIRD STEP
  args.app.use((req, res, next) => {
    // Oauth2 Provider returns auth code so that access_token can be obtained

    if (req.url.indexOf('/auth/callback') === 0) {
      console.debug('/auth/callback');
      oauth2.getOAuthAccessToken(
          req.query.code,
          {redirect_uri: settings.ep_oauth.callbackURL},
          (e, access_token, refresh_token, results) => {
            if (e) {
              // General Error
              console.error(e);
              res.end(e);
            } else if (results.error) {
              // Error in Results
              console.error('error in results', results);
              // res.end(JSON.stringify(results));
            } else {
              // Everything is all good, we have an access token for this user
              console.debug('Obtained access_token: ', access_token);

              const sessionID = req.query.state;

              // CAKE TODO
              // At the moment this is github specific..  This should be more "general.."

              // Getting user details
              const requestUrl = `https://api.github.com/user?access_token=${access_token}`;
              const rOptions = {
                url: requestUrl,
                headers: {
                  'User-Agent': 'request',
                },
              };
              request(rOptions, (error, response, body) => {
                if (!error && response.statusCode === 200) {
                  const user = JSON.parse(body);
                  const userBlob = {
                    access_token,
                    userInfo: user,
                  };
                  console.debug('Database Write -> ', sessionID, '---', userBlob);
                  db.set(`oauth:${sessionID}`, userBlob);
                } else {
                  console.error(error, response, body);
                }
              });

              next(); // Go to final step
            }
          });
    } else {
      next(); // Go to final step
    }
  });

  // FOURTH AND FINAL STEP
  args.app.get('/auth/callback', (req, res) => {
    // Read redirect lookup URL from database
    db.get(`oauthredirectlookup:${req.query.state}`, (k, url) => {
      console.debug('Oauth redirect lookup record found', url);
      // Send the user to the pad they were trying to access
      // Note that we could lookup the user data and append it so suggest their name
      // Or we might lookup this users UID in some form of permission table
      // Either way we have that data and can get to it by db.get("oauth:"+req.query.state,...
      res.redirect(url || '/');
    });
  });
};

// FIRST STEP
exports.authorize = (hookName, args, cb) => {
  // Never lands here for url /auth/callback
  if (args.req.url.indexOf('/auth') === 0) return cb.true;

  let userIsAuthedAlready = false;
  console.debug(`Database lookup -> oauth:${args.req.sessionID}`);
  db.get(`oauth:${args.req.sessionID}`, (k, user) => {
    console.debug(`Oauth session found ->${args.req.sessionID}`, 'has user data of ', user);
    if (user) userIsAuthedAlready = true;
  });
  return cb([userIsAuthedAlready]);
};

// SECOND STEP
exports.authenticate = (hookName, args, cb) => {
  console.debug(`Database Write -> oauthredirectlookup:${args.req.sessionID}`, '---', args.req.url);
  db.set(`oauthredirectlookup:${args.req.sessionID}`, args.req.url);
  // User is not authorized so we need to do the authentication step
  // Gets an authoritzation URL for the user to hit..

  // CAKE TODO -- we use redirect url as state, this seems wrong to me.
  const authURL = oauth2.getAuthorizeUrl({
    redirect_uri: settings.ep_oauth.callbackURL,
    scope: ['user'],
    state: args.req.sessionID,
    target: args.req.url,
  });

  args.res.redirect(authURL);
  // CAKE TODO -- This redirect fires a server console error because of when it's fired
  // It might make more sense to send this redirect as a browser script or so..
  // Let's see if it causes issues and if it does we can address it then..

  return cb([true]);
};
