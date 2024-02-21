//jshint esversion:6
require('dotenv').config() //after this it will be active and running
const express = require("express");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
var findOrCreate = require('mongoose-findorcreate')

const app = express();

app.set('view engine', 'ejs');

app.use(express.urlencoded({extended: true}));
app.use(express.static(__dirname + '/'))

app.use(session({
  secret: process.env.LOCAL_SECRET,
  resave: false,
  saveUninitialized: false
}))
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://127.0.0.1:27017/secretsDB");

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);
passport.use(User.createStrategy());
passport.serializeUser(function(user, done) {
  done(null, user);
});
passport.deserializeUser(function(user, done) {
  done(null, user);
});
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secret",
    userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {           //this callback gets implemented after authentication is successful
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {   //finding the user by their googleid in our db.....or creating them as a user on our db
      return cb(err, user);
    });
  }
));

app.get('/',(req,res)=>{
  res.render("home");
})
app.get('/auth/google',
  passport.authenticate("google", { scope: ["profile"] }));

app.get('/auth/google/secret',
    passport.authenticate("google", { failureRedirect: "/login" }),
    function(req, res) {
      // Successful authentication, redirect to secrets.
      res.redirect("/secrets");
});
app.get('/login',(req,res)=>{
  console.log(req.query);
  res.render("login", {error: req.query.error, err: req.query.err});
})
app.get('/register',(req,res)=>{
  console.log(req.query);
  displayerror = [];
  if(req.query.error)
  {
    err=req.query.err;
    displayerror = err.split(':');
    console.log(displayerror[1]);
  }
  res.render("register", {error: req.query.error, err: displayerror[1]});
  // res.render("register", {error: req.query.error, err: req.query.err});
})
app.get('/secrets',(req,res)=>{
    let sess = req.session;
    console.log(sess);
    res.set(
        'Cache-Control',
        'no-cache, private, no-store, must-revalidate, max-stal e=0, post-check=0, pre-check=0'
    );
    if(req.isAuthenticated())
      res.render("secrets", {username: sess.passport.user.username});
    else
      res.redirect("/login");
})
app.get('/logout',(req,res)=>{
  req.logout(function(err) {
    if (err) { console.log(err); }
    else
      res.redirect('/');
  });
})
app.get('/submit', (req,res)=>{
  if(req.isAuthenticated())
    res.render("submit");
  else
    res.redirect("/login");
})

app.post("/register",(req,res)=>{
  User.register({username:req.body.username}, req.body.password, function(err, user){    //registering
    if(err)
    {
      console.log(err);
      const error = 1;
      res.redirect(`/register?err=${err}&error=${error}`);
    }else{
      passport.authenticate("local")(req,res,function(){  //...authenticating....creating cookies
        res.redirect("/secrets");
      })
    }
  })
})

app.post("/login", function(req, res){
  //check the DB to see if the username that was used to login exists in the DB
  User.findOne({username: req.body.username})
  .then((foundUser)=>{
      if(foundUser){
        const user = new User({
          username: req.body.username,
          password: req.body.password
        });
      passport.authenticate("local", function(err, user){
        if(err){
          console.log(err);
          const er="authentication failed";
          const error=1;
          res.redirect(`/login?err=${er}&error=${error}`);
        } else {
            if(user){
              req.login(user, function(err){
                res.redirect("/secrets");
              });
            } else {
              const err="password doesnt match with the given username";
              const error=1;
              res.redirect(`/login?err=${err}&error=${error}`);
            }
        }
      })(req, res);
    //if no username is found at all, redirect to login page.
    } else {
      //user does not exists
      const err="No user found with the given username";
      const error=1;
      res.redirect(`/login?err=${err}&error=${error}`);
    }
  })
});

app.post("/submit", (req,res)=>{
  console.log(req.user);
    User.findById(req.user)
      .then(foundUser => {
        if (foundUser) {
          foundUser.secret = req.body.secret;
          return foundUser.save();
        }
        return null;
      })
      .then(() => {
        res.redirect("/secrets");
      })
      .catch(err => {
        console.log(err);
      });
});

app.listen(3000, function() {
  console.log("Server started on port 3000");
});
