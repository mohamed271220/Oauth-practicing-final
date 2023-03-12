//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
// const encrypt = require('mongoose-encryption')
//for hashing
// const md5 = require('md5')
// for hashing + salting
// const bcrypt = require('bcrypt')
// const saltRounds = 10;
//now level 5 of security passport
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs')
app.use(bodyParser.urlencoded({
    extended: true
}));

//session placement right here 
// poiller plat
app.use(session({
    secret: "OUR LIL SECRET THAT LIL BRO IS LIL BRO FOR HIS LIL BRO",
    resave: false,
    saveUninitialized: false
}))


app.use(passport.initialize());
app.use(passport.session())
////////////////////////////////////////


mongoose.connect("mongodb://127.0.0.1:27017/userDB", { useNewUrlParser: true });
mongoose.set("useCreateIndex", true)

/** proper schema writing syntax  */
const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    // A unique identifier for google account
    googleId: String,
    secret: String
});

// userSchema.plugin(encrypt,{secret:secret}) to encrypt everything
// userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] })
// now for hashing which is way better

//plugin for bcrypte
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);


const User = new mongoose.model("User", userSchema);


// pp code for bcrypt order matters 
passport.use(User.createStrategy());

//simplified code for serializing and deserializing
// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());

// this should work with any kind of authentication
passport.serializeUser(function (user, done) {
    done(null, user.id);
});
passport.deserializeUser(function (id, done) {
    User.findById(id, function (err, user) {
        done(err, user);
    });
});

//oauth code 
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
    function (accessToken, refreshToken, profile, cb) {
        console.log(profile);


        User.findOrCreate({ googleId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));

app.get('/', (req, res) => {
    res.render('home')
})

/** authentication Route (usually check the doc for it)  */
app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile'] })
);
/**  the redirect  */
// the app.get route has to match the one we specified 
app.get('/auth/google/secrets',
    passport.authenticate('google', { failureRedirect: '/login' }),
    function (req, res) {
        // Successful authentication, redirect home.
        res.redirect('/secrets');
    });


/*              login routing            */
app.route('/login')

    .get((req, res) => {
        res.render('login')
    })
    .post((req, res) => {
        // const username = req.body.username;
        // const password = req.body.password;

        // User.findOne({ email: username }, (err, foundUser) => {
        //     if (err) {
        //         console.log(err);
        //     } else {
        //         if (foundUser) {
        //             //hashing the password user entered then comparing it to database
        //             bcrypt.compare(password, foundUser.password, (err, result) =>{
        //                 if (result){
        //                     res.render("secrets");
        //                 };
        //             })
        //         }
        //     }
        // });

        /* passport security    --check passport documentation for a reference  */
        const user = new User({
            username: req.body.username,
            password: req.body.password
        })
        /** built in method */
        req.login(user, function (err) {
            if (err) {
                console.log(err);
            } else {
                passport.authenticate("local")(req, res, function () {
                    res.redirect('/secrets');
                });
            }
        })
    })
    .get((req, res) => {
        res.render('login')
    })


/** the secrets page route */
app.get("/secrets", (req, res) => {
    // mongoose field not null function ===  {$ne:null}
    User.find({ "secret": { $ne: null }}, (err , foundUser)=>{
        if (err){
            console.log(err);
        } else {
            if (foundUser){
                res.render('secrets', {usersWithSecret: foundUser});
            }
        }
    })
});

/** submit page */
app.get('/submit', (req, res) => {
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login")
    }
})

app.post("/submit", (req, res) => {
    const submittedSecret = req.body.secret;

    User.findById(req.user.id, (err, user) => {
        if (err) {
            console.log(err);
        } else {
            if (user) {
                user.secret = submittedSecret;
                user.save(() => {
                    res.redirect("/secrets");
                });
            }
        }
    })
})

/** logout route */

app.get("/logout", function (req, res) {
    req.logout(() => { });
    res.redirect('/');
})


/*  register routing */
app.route('/register')
    .get((req, res) => {
        res.render('register')
    })
    .post((req, res) => {
        /* hashing +20 rounds of salting */
        // bcrypt.hash(req.body.password, saltRounds, (err, hash) => {
        //     const newUser = new User({
        //         email: req.body.username,
        //using md5 for hashing 
        // password: md5(req.body.password),
        //using hash + salt (bcrypt)
        //         password: hash,
        //     });
        //     newUser.save((err) => {
        //         if (err) {
        //             console.log(err);
        //         } else {
        //             res.render("secrets");
        // as there is no special routing for secrets this is the only way user access the secret page
        //         }
        //     });
        // });
        // passport security
        User.register({ username: req.body.username }, req.body.password, (err, user) => {
            if (err) {
                console.log(err);
                res.redirect('/register')
            } else {
                passport.authenticate("local")(req, res, () => {
                    res.redirect("/secrets")
                })
            }
        })


    });











app.listen(3000, function () {
    console.log("server listening on port 3000");
})