//jshint esversion:6
require('dotenv').config() //after this it will be active and running
const express = require("express");
const ejs = require("ejs");
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption");

const app = express();

app.set('view engine', 'ejs');

app.use(express.urlencoded({extended: true}));
app.use(express.static(__dirname + '/'))
mongoose.connect("mongodb://127.0.0.1:27017/secretsDB");

const userSchema = new mongoose.Schema({
  email: String,
  password: String
});

// const secret = "Thisisoursecret.";
userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ["password"]}); //above mongoose.model

const User = mongoose.model("User", userSchema);

app.get('/',(req,res)=>{
  res.render("home");
})
app.get('/login',(req,res)=>{
  res.render("login");
})
app.get('/register',(req,res)=>{
  res.render("register");
})
//no get for /secrets route bcoz we dont want to render the secrets page unless the user is registered or logged in

app.post("/register",(req,res)=>{
  const newUser = new User({
    email: req.body.username,
    password: req.body.password
  });
  newUser.save()
  .then(()=>{
    res.render("secrets");
  })
  .catch((err)=>{
    console.log("Error in registering user- save", err);
  })
})

app.post("/login", (req,res)=>{
  const username = req.body.username;
  const password = req.body.password;

  User.findOne({email: username})
  .then((foundUser)=>{
    if(foundUser)
    {
      if(foundUser.password === password)
        res.render("secrets");
      else
        res.send("Wrong password");
    }
    else
      res.send("This email is not registered");
  })
  .catch((err)=>{
    console.log("Error in logging in - findOne", err);
  })
})

app.listen(3000, function() {
  console.log("Server started on port 3000");
});
