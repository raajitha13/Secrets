//jshint esversion:6
require('dotenv').config() //after this it will be active and running
const express = require("express");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

const app = express();

app.set('view engine', 'ejs');

app.use(express.urlencoded({extended: true}));
app.use(express.static(__dirname + '/'))

app.use(session({
  secret: process.env.LOCAL_SECRET,
  resave: false,
  saveUninitialized: false
}))
app.use(passport.initialize());   //telling our app to use passport and initialize passport package
app.use(passport.session()); //use passport for dealing w sessions

mongoose.connect("mongodb://127.0.0.1:27017/secretsDB");
// mongoose.set("useCreateIndex",true);

const userSchema = new mongoose.Schema({
  email: String,
  password: String
});

userSchema.plugin(passportLocalMongoose);

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

app.get('/',(req,res)=>{
  res.render("home");
})
app.get('/login',(req,res)=>{
  res.render("login");
})
app.get('/register',(req,res)=>{
  res.render("register");
})
app.get('/secrets',(req,res)=>{
    // The below line was added so we can't display the "/secrets" page
    // after we logged out using the "back" button of the browser, which
    // would normally display the browser cache and thus expose the
    // "/secrets" page we want to protect. Code taken from this post.
    res.set(
        'Cache-Control',
        'no-cache, private, no-store, must-revalidate, max-stal e=0, post-check=0, pre-check=0'
    );
  if(req.isAuthenticated())
    res.render("secrets");
  else
    res.render("login");
})
app.get('/logout',(req,res)=>{
  req.logout(function(err) {
    if (err) { console.log(err); }
    else
      res.redirect('/');
  });
})

app.post("/register",(req,res)=>{
  User.register({username:req.body.username}, req.body.password, function(err, user){    //registering
    if(err)
    {
      console.log(err);
      res.redirect("/register");
    }else{
      passport.authenticate("local")(req,res,function(){  //...authenticating....creating cookies
        res.redirect("/secrets");
      })
    }
  })
})

// app.post("/login", (req,res)=>{
//   const user = new User({
//     username: req.body.username,
//     passport: req.body.passport
//   });                               //we are not saving this user but we are just using to authenticate
//
//   req.login(user, function(err){
//     if(err)
//       console.log(err);
//     else
//     {
//       passport.authenticate("local")(req,res,function(){   //if logged in successfully...authenticating....creating cookies
//         res.redirect("/secrets");
//       })
//     }
//   })
// })
//The reason why your code isn't fixing it is because the user is still being authenticated even when the password is incorrect.
// As long as the username is found, Passport will authenticate them (regardless of whether the password was correct).  This is because Angela used "req.login" before Passport checked the login credentials.  "req.login" will sign the user in.

//req.login is invoked automatically when passport.authenticate is successful, but she does it manually before calling passport.authenticate. so using this code

// app.post("/login", passport.authenticate("local"), function(req, res){
//     res.redirect("/secrets");
// });

//this can also be used
// app.post('/login', passport.authenticate('local', {
//                             successRedirect: '/secrets',
//                             failureRedirect: '/login'
//                             })
// );

app.post("/login", function(req, res){
  //check the DB to see if the username that was used to login exists in the DB
  User.findOne({username: req.body.username})
  .then((foundUser)=>{
    //if username is found in the database, create an object called "user" that will store the username and password
    //that was used to login
      if(foundUser){
        const user = new User({
          username: req.body.username,
          password: req.body.password
        });
      //use the "user" object that was just created to check against the username and password in the database
      //in this case below, "user" will either return a "false" boolean value if it doesn't match, or it will
      //return the user found in the database
      passport.authenticate("local", function(err, user){
        if(err){
          console.log(err);
        } else {
          //this is the "user" returned from the passport.authenticate callback, which will be either
          //a false boolean value if no it didn't match the username and password or
          //a the user that was found, which would make it a truthy statement
            if(user){
              //if true, then log the user in, else redirect to login page
              req.login(user, function(err){
                res.redirect("/secrets");
              });
            } else {
              res.redirect("/login");
            }
        }
      })(req, res);
    //if no username is found at all, redirect to register page.
    } else {
      //user does not exists
      res.redirect("/register")
    }
  })
});

app.listen(3000, function() {
  console.log("Server started on port 3000");
});
