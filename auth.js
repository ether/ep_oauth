var db = require('ep_etherpad-lite/node/db/DB').db;
settings = require('../../src/node/utils/Settings');
var cookieParser = require('ep_etherpad-lite/node_modules/cookie-parser');
var session = require('ep_etherpad-lite/node_modules/express-session');
var passport = require('passport');
var GitHubStrategy = require('passport-github').Strategy;

passport.use(new GitHubStrategy({
    clientID: settings.ep_oauth.clientID,
    clientSecret: settings.ep_oauth.clientSecret,
    callbackURL: settings.ep_oauth.callbackURL
  },
  function(accessToken, refreshToken, profile, done) {
    // asynchronous verification, for effect...
    process.nextTick(function () {
      // To keep the example simple, the user's GitHub profile is returned to
      // represent the logged-in user.  In a typical application, you would want
      // to associate the GitHub account with a user record in your database,
      // and return that user instead.
      console.warn("successful auth");
      return done(null, profile);
    });
  }
));

exports.expressConfigure = function(hook_name, args, cb) {

  args.app.use(passport.initialize());
  args.app.use(passport.session());

  args.app.get('/auth/github', passport.authenticate('github'));
  args.app.get('/auth/callback', 
    passport.authenticate('github', { failureRedirect: '/auth/github' }),
    function(req, res) {
      // Successful authentication, redirect home.
      res.redirect('/');
    }
  );

  args.app.use(function(req, res, next) {
    if (req.path.match(/^\/(static|javascripts|pluginfw|locales|favicon|oauth|auth)/)) {
      console.warn("straight through", req.path);
      // Don't ask for github auth for static paths or for oauth url?
      next();
    } else {
      console.error("not straight through", req.path);
      if(req.path.indexOf("/p") === 0){
        console.warn("isAuth", req.isAuthenticated());
        if (req.isAuthenticated()){ 
          console.warn("is authenticated!");
          return next(); 
        }else{
          console.warn("passing back to auth as not authenticated");
          res.redirect('/auth/github');
        }
      }
    }
  });

}

// Passport session setup.
//   To support persistent login sessions, Passport needs to be able to
//   serialize users into and deserialize users out of the session.  Typically,
//   this will be as simple as storing the user ID when serializing, and finding
//   the user by ID when deserializing.  However, since this example does not
//   have a database of user records, the complete GitHub profile is serialized
//   and deserialized.
passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(obj, done) {
  done(null, obj);
});
