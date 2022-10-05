const fs = require('fs');
const https = require('https');
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const passport = require('passport');
const { Strategy } = require('passport-google-oauth20');
const cookieSession = require('cookie-session')

require('dotenv').config(); // get values from .env file

const PORT = 3001;

const config = {
    CLIENT_ID: process.env.CLIENT_ID,  // built in process
    CLIENT_SECRET: process.env.CLIENT_SECRET,
    COOKIE_KEY_1: process.env.COOKIE_KEY_1,
    COOKIE_KEY_2: process.env.COOKIE_KEY_2,
};

// determine how passport authenticates users, options are on googleCloud credential
const AUTH_OPTIONS = {
    callbackURL: '/auth/google/callback',
    clientID: config.CLIENT_ID,
    clientSecret: config.CLIENT_SECRET,
}
// called when users are authenticated
function verifyCallback(accessToken, refreshToken, profile, done) {
    console.log('Google profile', profile);
    done(null, profile); // call done if tokens are valid call passport with the user who is authenticated or error (first argument)
}

passport.use(new Strategy(AUTH_OPTIONS, verifyCallback))

// Save the session to the cookie
// executes whenever userdata is being saved to the cookie
// done is a callback in case we need to do any asynchronous work to serialize the user
passport.serializeUser((user, done) => {
    done(null, user);
});

// Read the session from the cookie
// takes in object from our session and returns back the data that will
// be made available inside of Express on the request.user
passport.deserializeUser((obj, done) => {
    done(null, obj);
})

const app = express();

// secure endpoints with helmet, protect against common configuration issues
app.use(helmet()); // all routes pass through helmet

app.use(cookieSession({
    name: 'session',
    maxAge: 24 * 60 * 60 * 1000, // 1 day
    keys: [config.COOKIE_KEY_1, config.COOKIE_KEY_2]
}))
app.use(passport.initialize()); //sets up passport session

// middleware so Passport understands our cookie session and the request.use object
// authenticates the session, validates everything signed as should be
// allows deserialize function to be called and set req.user
app.use(passport.session());

function checkLoggedIn(req, res, next) {
    const isLoggedIn = true;
    if (!isLoggedIn) {
        return res.status(401).json({
            error: 'You must log in!',
        })
    }
    next();
}

app.get('/auth/google', 
  passport.authenticate('google', {
    scope: ['email']
  })
);

// where authorization code is exchanged for an access token
// path set in googlecloud credential api
app.get('/auth/google/callback', 
  passport.authenticate('google', { //middleware
    failureRedirect: '/failure' ,   // options for failing or successful authenticate
    successRedirect: '/',
    session: true,       // save session and serialize it in a cookie
  }), 
  (req, res) => {   // third parameter is request handler, could redirect here if desired vs above
    console.log('Google called us back!');
  }
);

app.get('/auth/logout', (req, res) => {

});

app.get('/secret', checkLoggedIn, (req, res) => { // pass in middleware for this route, can be multiple functions
    return res.send('Your personal secret value is 42!')
});

app.get('/failure', (req, res) => {
    return res.send('Failed to log in!');
})

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html')); //__dirname ensures path is valid on any operating system
});

https.createServer({    //listen using https
    key: fs.readFileSync('key.pem'), //certificate and key from OpenSSL for secure server
    cert: fs.readFileSync('cert.pem'),
}, app).listen(PORT, () => { 
//app.listen(PORT, () => { // using express
    console.log(`Listening on port ${PORT}`);
});