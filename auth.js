var db = require('ep_etherpad-lite/node/db/DB').db;
settings = require('../../src/node/utils/Settings');
var cookieParser = require('ep_etherpad-lite/node_modules/cookie-parser');
var session = require('ep_etherpad-lite/node_modules/express-session');
var sessionStore = require('ep_etherpad-lite/node/db/SessionStore');

var OAuth2 = require('./node_modules/oauth/lib/oauth2').OAuth2;

var oauth2 = new OAuth2(settings.ep_oauth.clientID,
  settings.ep_oauth.clientSecret,
  'https://github.com/', 
  'login/oauth/authorize',
  'login/oauth/access_token',
  null); /** Custom headers */

exports.expressConfigure = function(hook_name, args, cb) {

  
/*
  args.app.use(function(req, res, next) {

    if(req.path.indexOf("/login") === 0){
      console.log("Trying to access a pad", req.path);

      var authURL = oauth2.getAuthorizeUrl({
        redirect_uri: settings.ep_oauth.callbackURL,
        scope: ['repo', 'user'],
        state: 'herpDERPCHANGEMEINSETTINGS'
      });

      var body = '<a href="' + authURL + '"> Get Code </a>';
      res.writeHead(200, {
       'Content-Length': body.length,
       'Content-Type': 'text/html' });
      res.end(body);
 
      // console.warn(authURL);
      return next();
    }else{
      return next();
    }

  });
*/

  args.app.get('/auth/callback', function(req, res){
    /** Github sends auth code so that access_token can be obtained */
    /** Obtaining access_token */
    oauth2.getOAuthAccessToken(
      req.query.code,
      {'redirect_uri': settings.ep_oauth.callbackURL},
      function (e, access_token, refresh_token, results){
      if (e) {
        console.log(e);
        res.end(e);
      } else if (results.error) {
        console.log(results);
        res.end(JSON.stringify(results));
      }
      else {
        console.log('Obtained access_token: ', access_token);
        req.session.ep_oauth = access_token;
        // I need to figure out what to do with this?  Do I store it against the users sessionID?
        // We should store it against the user in the SessionManager and flag that user as "authenticated"
        // Here I wanna set req.session.user to be true? 
        // then I wanna do the check in req.authorize
        res.end( access_token);
      }
    });
  });

}


exports.authorize = function(hook_name, args, cb){
  console.warn("authorize args");
  var userIsAuthedAlready = false;
  var user = args.req.session.user;
  return cb([userIsAuthedAlready]);
}

exports.authenticate = function(hook_name, args, mangle){
  // User is not authorized so we need to do the authentication step
  if(args.req.url !== '/oauth/login'){
  console.log(args.req);
    args.res.redirect('/oauth/login');
  }
}

