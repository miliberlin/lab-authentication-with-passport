const express = require('express');
const router = express.Router();
const User = require('../models/User.model');
const bcrypt = require('bcrypt');
const passport = require('passport');

router.get('/signup', (req,res,next) => {
  res.render('auth/signup')
})

router.post('/signup', (req, res, next) => {
  const { username, password } = req.body;
  if (password.length < 8) {
    res.render('auth/signup', { message: 'Your password has to be at least 8 characters.' });
    return
  }
  if (username === '') {
    res.render('auth/signup', { message: 'Your username can not be empty.' });
    return
  }

  User.findOne({ username: username })
  .then(userFromDB => {
    // if user exists -> we render signup again
    if (userFromDB !== null) {
      res.render('auth/signup', { message: 'This username is already taken' });
    } else {
      // the username is available
      // we create the hashed password
      const salt = bcrypt.genSaltSync();
      const hash = bcrypt.hashSync(password, salt);
      console.log(hash);
      // create the user in the database
      User.create({ username: username, password: hash })
        .then(createdUser => {
          console.log(createdUser);
          // log the user in immediately
          // req.session.user = createdUser; -> this is the 'node-basic'auth-way'
          // this is the passport login
          req.login(createdUser, err => {
            if (err) {
              next(err);
            } else {
              res.redirect('/');
            }
          })
          // redirect to login
          res.redirect('/login');
        })
    }
  })
})

router.get('/login', (req,res,next) => {
  res.render('auth/login')
})

router.post('/login', passport.authenticate('local', {
  successRedirect: '/',
  failureRedirect: '/login',
  passReqToCallback: true
}));

router.get('/logout', (req, res, next) => {
  // this is a passport function
  req.logout();
  res.redirect('/');
});

// middleware to check login
const ensureLogin = require('connect-ensure-login');

router.get('/private-page', ensureLogin.ensureLoggedIn(), (req, res) => {
  res.render('auth/private', { user: req.user });
});

module.exports = router;
