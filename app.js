var express = require('express');
var bcrypt = require('bcryptjs');
var bodyParser = require('body-parser');
var mongoose = require('mongoose');
var sessions = require('client-sessions');
var csrf = require('csurf');

mongoose.Promise = global.Promise;

var uri = 'mongodb://localhost/auth';
mongoose.connect(uri, { useMongoClient: true });

var Schema = mongoose.Schema;
var ObjectId = Schema.ObjectId;

var app = express();
app.set('view engine', 'pug');
app.locals.pretty = true;


var User = mongoose.model('User', new Schema({
  id:           ObjectId,
  firstName:    { type: String, required: '{PATH} is required.' },
  lastName:     { type: String, required: '{PATH} is required.' },
  email:        { type: String, required: '{PATH} is required.', unique: true },
  password:     { type: String, required: '{PATH} is required.' },
  data:         Object,
}));



// middleware
app.use(bodyParser.urlencoded({ extended: true }));

app.use(sessions({
    cookieName: 'session',
    secret: 'razorsharp23',
    duration: 30 * 60 * 1000,
    activeDuration: 5 * 60 * 1000
}));

app.use(csrf());

app.use(function(req, res, next) {
    if (req.session && req.session.user) {
        User.findOne({email: req.session.user.email }, function(err, user) {
            if (user) {
                req.user = user;
                delete req.user.password;
                req.session.user = req.user;
                res.locals.user = req.user;
            }
            next();
        });
    } else {
        next();
    }
});

function requireLogin(req, res, next) {
    if (!req.user) {
        res.redirect('/login');
    }else {
        next();
    }
}


app.get('/', function(req, res) {
    if (req.session && req.session.user) {
        User.findOne({ email: req.session.user.email }, function(err, user) {
            if (!user) {
                res.render('index.pug');
            } else {
                res.locals.user = user;
                res.render('dashboard.pug');
            }
        });
    } else {
        res.render('index.pug');
    }
});

app.get('/register', function(req, res) {
    res.render('register.pug', { csrfToken: req.csrfToken() });
});

app.post('/register', function(req, res) {
    var hash = bcrypt.hashSync(req.body.password, bcrypt.genSaltSync(10));
    var user = new User({
        firstName: req.body.firstName,
        lastName: req.body.lastName,
        email: req.body.email,
        password: hash
    });
    user.save(function(err) {
        if (err) {
            var err = "Something fucked up. good job genius.";
            if (err.code == 11000) {
                error = 'That email is already taken. you trying to steal?';
            }
            res.render('register.pug', { error: error });
        }else {
            req.session.user = user;
            res.redirect('/dashboard');
        }
    });
});


app.get('/login', function(req, res) {
    res.render('login.pug', { csrfToken: req.csrfToken() });
});

app.post('/login', function(req, res) {
    User.findOne({ email: req.body.email }, function(err, user) {
        if(!user) {
            res.render('login.pug', { error: "Invalid email or password." });
        } else {
            if (bcrypt.compareSync(req.body.password, user.password)) {
                req.session.user = user;
                res.redirect('/dashboard');
            } else {
                res.render('login.pug', { error: 'Invalid Email or Passord.'});
            }
        }    
    });
});

app.get('/dashboard', requireLogin, function(req, res) {
    res.render('dashboard.pug');
});

app.get('/logout', function(req, res) {
    req.session.reset();
    res.redirect('/');
});

app.listen(3000);
console.log('Your app is running on port: 3000');