var express     = require('express');
var app         = express();
var port        = process.env.PORT || 80;
var formidable  = require('formidable');
var exec        = require('child_process').exec;
var fs          = require('fs');
var cors        = require('cors');
var glob        = require('glob');
var bcrypt      = require('bcrypt');
var async       = require('async');

var bodyParser      = require('body-parser');
var cookieParser    = require('cookie-parser');
var session         = require('express-session');
var MongoClient     = require('mongodb').MongoClient;
var ObjectID        = require('mongodb').ObjectID;
var mandrill        = require('node-mandrill')('DIE-Gm5EhIT4k_u8R-VhhQ');
var crypto          = require('crypto');

var db  = null;

// Make sure the following directories exist.
// For ffmpeg and sox make sure the appropriate binaries exist at the given path.
var AUDIO_DATA_DIR    = '/home/ec2-user/emotion-audio-data';
var FFPMEG_PATH       = 'ffmpeg/ffmpeg';
var SOX_PATH          = '/var/emotion-data/sox/src/sox';

var columnizer = function(){
    var columns = [],
        numRows = 0;

    return{
        addColumn: function(c){
            columns.push(c);
            if(c.length > numRows){
                numRows = c.length;
            }
        },

        generate: function(){
            var res = '';

            for(var i = 0; i<numRows; i++){
                for(var j = 0; j < columns.length; j++){
                    var col = columns[j];
                    if(i < col.length){
                        res += col[i];
                    }

                    if( j < (columns.length - 1)){
                        res += ',';
                    }
                    else{
                        res += '%0A';
                    }
                }
            }

            return res;
        }
    };
};

function findMedian(values) {
    values.sort( function(a,b) {return a - b;} );

    var half = Math.floor(values.length/2);

    if(values.length % 2)
        return values[half];
    else
        return (values[half-1] + values[half]) / 2.0;
}

var findAverage = function(a) {
    var r = {mean: 0, variance: 0, deviation: 0}, t = a.length;
    for(var m, s = 0, l = t; l--; s += a[l]);
    for(m = r.mean = s / t, l = t, s = 0; l--; s += Math.pow(a[l] - m, 2));
    return r.deviation = Math.sqrt(r.variance = s / t), r;
};

function isEmail(email) { 
    var re = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test(email);
} 

app.use('/static', express.static('static'));
app.use(cookieParser());
app.use(session({secret: 'Tpf3aI4Y&2EX7oOTNM08fq5431Y`20', saveUninitialized: true, resave: true}));
app.set('view engine', 'jade');

app.use(function (req, res, next) {
    var err = req.session.error,
        msg = req.session.success,
        flash = req.session.flash;

    delete req.session.error;
    delete req.session.success;
    delete req.session.flash;
    res.locals.message = '';
    if (err) res.locals.message = '<p class="msg error">' + err + '</p>';
    if (msg) res.locals.message = '<p class="msg success">' + msg + '</p>';
    for(f in flash) {
        res.locals[f] = flash[f];
    }
    next();
});

function authenticate(email, password, fn) {
    if (!module.parent) console.log('Authenticating %s:%s', email, password);
    Users = db.collection('users');
    Users.findOne({ email: email },
        function (err, user) {
            if (user) {
                if (err) return fn(new Error('Cannot find user %s', user));
                if(user.approved && bcrypt.compareSync(password, user.password)) {
                    return fn(null, user);
                }
                fn(new Error('Invalid password'));
            } else {
                return fn(new Error('Cannot find user.'));
            }
        }
    );

}

function ensureAuthenticated(req, res, next) {
    if (req.session.user) {
        next();
    } else {
        res.redirect('/login');
    }
}

function ensureAuthenticatedModerator(req, res, next) {
    if (req.session.user && req.session.user.role <= 1) {
        next();
    } else {
        res.send('Access denied');
    }    
}

app.get('/', ensureAuthenticated, function(req, res) {
    Users = db.collection('users');
    Users.find({}).toArray(function(err, docs){
        if(err) {
            console.error(err);
            return res.status(500).send('Server error.');
        }

        var approve = [], users = [];
        for(var i = 0; i < docs.length; i++) {
            if(docs[i].role == 0) continue;
            if(docs[i].approved == false) {
                approve.push(docs[i]);
            }
            else {
                users.push(docs[i]);
            }
        }
        res.render('index', { approve: approve, users: users, admin: req.session.user });  
    });
});

app.get('/login', function(req, res){
    res.render('login');
});

app.post( '/login', bodyParser.urlencoded({ extended: false }), function (req, res) {
    authenticate(req.body.email, req.body.password, function (err, user) {
        if (user) {
            req.session.regenerate(function () {
                req.session.user = user;
                res.redirect('/');
            });
        } else {
            req.session.error = 'Please check your ' + ' email and password.';
            res.redirect('/login');
        }
    });
});

app.post( '/update', ensureAuthenticated, bodyParser.json(), function (req, res) {
    var update = {}, id = req.body.id || '';
    if(id === '') {
        return res.send({error: 'User id required.'});
    }
    id = new ObjectID(id);
    if(req.body.approved !== undefined) update.approved = req.body.approved;
    if(req.body.role !== undefined) update.role = req.body.role;

    Users = db.collection('users');
    Users.update({'_id': id}, {$set: update}, {w: 1}, function(err, result) {
        if(err) {
            return res.status(500).send({error: 'Error updating user.'})
        }

        Users.findOne({'_id': id}, function(err, doc) {
            if(err) {
                return console.log( JSON.stringify(err) );
            }
            
            if(update.approved == true) {
                mandrill('/messages/send', {
                    message: {
                        to: [{name: doc.name, email: doc.email}],
                        from_email: 'updates@emotiontracker.com',
                        from_name: "Emotiontracker admin",
                        subject: 'Experimenter registration approved!',
                        text: 'Dear ' + doc.name +',\n\nCongratulations! Your request to register as an experimenter on emotiontracker has been approved. You can upload new experiments within the app using the following credentials: \n\n Email: ' + doc.email + '\n Password: <Registered password> \n\n You can also login to the admin page at http://' + req.headers.host + '/login using the same credentials.' 
                    }
                }, function(error, response) {
                    if (error) console.log( JSON.stringify(error) );
                    else console.log(response);
                });            
            }
        });

        res.status(200).send({});
    });
});

app.get('/logout', function(req, res){
    req.session.destroy(function () {
        res.redirect('/login');
    });
});


app.get('/register', function(req, res) {
    res.render('register');
});

app.get('/forgot', function(req, res) {
    res.render('forgot');
});

app.post('/forgot', bodyParser.urlencoded({ extended: false }), function(req, res) {

    async.waterfall([
        function(done){
            crypto.randomBytes(20, function(err, buf) {
                var token = buf.toString('hex');
                done(err, token);
            });
        },

        function(token, done) {
            Users = db.collection('users');  
            Users.findAndModify(
                {email: req.body.email, approved: true}, 
                [['email', 1]], 
                {$set: {resetPassToken: token, resetPassExpires: Date.now() + 3600000}}, 
                {new:true}, 
                function(err, user) {
                    if(!user) {
                        req.session.error = 'No account with that email address exists.';
                        return res.redirect('/forgot');          
                    }
                    done(err, token, user);
                }
            );
        },

        function(token, user, done) {
            mandrill('/messages/send', {
                message: {
                    to: [{name: user.name, email: user.email}],
                    from_email: 'updates@emotiontracker.com',
                    from_name: "Emotiontracker admin",
                    subject: 'Emotiontracker password reset',
                    text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
                            'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
                            'http://' + req.headers.host + '/reset/' + token + '\n\n' +
                            'If you did not request this, please ignore this email and your password will remain unchanged.\n'
                }
            }, function(err, response) {
                req.session.flash = {
                    status: 1,
                    email: user.email
                }
                done(err);
            });            
        }

    ], function(err) {
        if(err){
            console.log( JSON.stringify(err) );
            return res.status(500);
        }
        res.redirect('/forgot');
    });
});

app.get('/reset/:token', function(req, res) {
    Users = db.collection('users');
    Users.findOne({ resetPassToken: req.params.token, resetPassExpires: { $gt: Date.now() } }, function(err, user) {
        if(!user) {
            req.session.error = 'Password reset token is invalid or has expired.';
            return res.redirect('/forgot');
        }
        res.render('reset');
    });
});

app.post('/reset/:token', bodyParser.urlencoded({ extended: false }), function(req, res) {

    async.waterfall([
        function(done){
            var password = req.body.password;
            if(password.length < 4 || password !== req.body.confirm) {
                req.session.error = 'Passwords don\'t match or is invalid.';
                return res.redirect('/reset/' + req.params.token);                
            }

            bcrypt.hash(password, 8, function(err, hash) {
                done(err, hash);
            });
        },

        function(hash, done) {
            Users = db.collection('users');
            Users.findAndModify(
                { resetPassToken: req.params.token, resetPassExpires: { $gt: Date.now() }}, 
                [['resetPassToken', 1]], 
                {$set: {password: hash}}, {$unset: {resetPassToken: '', resetPassExpires: ''}}, 
                {new:true}, 
                function(err, user) {
                    if(!user) {
                        req.session.error = 'Password reset token is invalid or has expired.';
                        return res.redirect('/forgot');
                    }
                    done(err, user);
                }
            );
        },

        function(user, done) {
            mandrill('/messages/send', {
                message: {
                    to: [{name: user.name, email: user.email}],
                    from_email: 'updates@emotiontracker.com',
                    from_name: "Emotiontracker admin",
                    subject: 'Your password has been changed',
                    text: 'Hi ' + user.name + '\n\n' +
                        'This is a confirmation that the password for your account ' + user.email + ' has just been changed.\n'
                }
            }, function(err, response) {
                req.session.success = 'Your password has been successfully changed.';
                done(err);
            });        
        }
    ], function(err) {
        res.redirect('/login');
    });
});


app.use(cors());
app.post('/register', bodyParser.json(), function(req, res) {

    var name = req.body.name,
        email = req.body.email,
        password = req.body.password,
        university = req.body.university || '',
        city = req.body.city || '';

    if (name == '' || !isEmail(email) || password == '') {
        return res.send({error: 'Invalid credentials.'});
    }

    bcrypt.hash(password, 8, function(err, hash) {
        var user = {
            "name": name,
            "email": email,
            "password": hash,
            "university": university,
            "city": city,
            "role": 2,
            "approved": false
        };

        Users = db.collection('users');
        Users.insert(user, {w: 1}, function(err, result) {
            if(err) {
                console.log(err);
                res.send({error: 'A user with the given email already exists.'});
            }
            else {
                Users.find({role:1}).toArray(function(err, docs) {
                    if(err) return console.log(err);
                    var to = [];
                    for(var i = 0; i < docs.length; i++) {
                        to.push({email: docs[i].email, name: docs[i].name});
                    }

                    mandrill('/messages/send', {
                        message: {
                            to: to,
                            from_email: 'updates@emotiontracker.com',
                            from_name: "Emotiontracker admin",
                            subject: '[Experimenter request] ' + user.name + ' - ' + user.university,
                            text: ''
                        }
                    }, function(error, response) {
                        if (error) console.log( JSON.stringify(error) );
                        else console.log(response);
                    });
                });
                res.send({success: 'Registration successful.'});
            }
        });        
    });

});

app.get('/users', function(req, res){
    var Users = db.collection('users');
    Users.find({approved: true, role: {$gt: 0}}, {_id: true, name: true}).toArray(function(err, docs){
        if(err){
            console.error('Users retrieval exception: ', err);
            return res.send({error:'Error fetching users.'});
        }
        res.send(docs);
    });
});

app.use('/rec', express.static(AUDIO_DATA_DIR + '/rec'));

app.post('/remove', function(req, res){
    try{
        var name = req.query.name.replace(/ /g,'');
        if(req.query.type == 'one'){
            fs.unlinkSync(AUDIO_DATA_DIR + name);
        }
        else if(req.query.type == 'all'){
            glob('rec/' + name + "-*", {}, function (er, files) {
                files.forEach(function(f){
                    fs.unlinkSync(AUDIO_DATA_DIR + f);
                });
            });        
        }
        res.end();        
    }
    catch(err){
        console.error(err, err.stack);
        res.end();
    }

});

app.post('/convert', function(req, res){

    var name = req.query.q.replace(/ /g,'');
    var type = '';
    
    if(req.query.t){
        type = req.query.t;
    }

    var fileid = (+new Date()).toString(36),
        tmpPath = AUDIO_DATA_DIR + 'rec/' + fileid + '.wav',
        intmPath = AUDIO_DATA_DIR + 'rec/' + name + '-' + fileid + '.wav',
        finalPath = 'rec/' + name + '-' + fileid + ((type == 'mac') ? '.ogg' : '.mp3');

    try{
        var form = new formidable.IncomingForm({ 
            uploadDir: AUDIO_DATA_DIR + 'tmp',
            keepExtensions: true
        });

        form.parse(req, function(err, fields, files) {
            var file = files.file;
            if(!file || !name){
                throw 'Incomplete parameters';
            }

            exec( FFPMEG_PATH + ' -y -i ' + file.path + ' -af "volumedetect" ' + tmpPath , function (error, stdout, stderr){

                if(error){
                    throw '[Ffmpeg error] ' + stderr;
                } 
                else{
                    var regex = /max_volume: (-?[0-9]\d*(\.\d+)?) dB/g;
                    var match = regex.exec(stderr);  
                    var gain = parseFloat(match[1]);
                    if(gain < 0){
                        gain *= -1;
                    }              
                    else{
                        gain = 0;
                    }                        
                }

                exec( SOX_PATH + ' ' + tmpPath + ' ' + intmPath + ' silence 1 0.3 1% reverse silence 1 0.3 1% reverse', function (error, stdout, stderr){
                    fs.unlinkSync(tmpPath);
                    if(error){
                        throw '[Sox error] ' + stderr;
                    }    
                    else{
                        exec( FFPMEG_PATH + ' -y -i ' + intmPath + ' -af "volume=' + gain + 'dB" ' + AUDIO_DATA_DIR + finalPath , function (error, stdout, stderr){
                            fs.unlinkSync(intmPath);
                            if(error){
                                throw '[Ffmpeg error] ' + stderr;
                            }
                            else{
                                res.send({path:finalPath});
                            }
                        });
                    }                        
                });

            });

        });        
    }
    catch(err){
        console.error('Conversion exception: ', err, err.stack);
        res.send({error:'Unable to process recording.'});
    }

});

app.get('/converted', function(req, res){
    try{
        var name = req.query.q.replace(/ /g,'');
        glob("rec/" + name + "-*", {cwd:AUDIO_DATA_DIR}, function (er, files) {
            res.send(files);
        });        
    }
    catch(err){
        console.error(err, err.stack);
        res.end();
    }

});

app.post('/upload', bodyParser.json(), function(req, res){
    var Users = db.collection('users');
    Users.findOne({email: req.body.email}, function(err, user) {
        if(!user || !bcrypt.compareSync(req.body.password, user.password)) {
            return res.send({error:'Invalid email or password'});    
        }

        var Settings = db.collection("settings");
        
        Settings.update({exp: req.body.e, users_id: user._id}, {$set: {options: req.body.o}}, {upsert: true}, function(err, obj){
            if(err){
                console.error('Settings storage exception: ', err);
                res.send({error:'Error saving settings'});
            }
            else{
                res.send({id: obj._id, user_id: user._id});
            }
            
        });
    });

});

app.get('/download', function(req, res){
    var settings = db.collection("settings");
    settings.findOne({_id: ObjectID(req.query.id)}, function(err, obj){
        if(err){
            console.error('Settings retrieval exception: ', err);
            return res.send({error:'Error fetching settings'});
        }
        res.send(obj || {});
    });
});

app.get('/exps', function(req, res){
    var settings = db.collection("settings");
    var query = {};
    if(req.query.id) {
        query.users_id = ObjectID(req.query.id);
    }
    settings.find(query, {_id: true, exp: true}).toArray(function(err, docs){
        if(err){
            console.error('Experiment retrieval exception: ', err);
            return res.send({error:'Error fetching experiments'});
        }
        res.send(docs);        
    });
});

app.post('/store', bodyParser.json(), function(req, res){
    if(!req.body) return res.sendStatus(400);

    var data = req.body;
    data.timeZero = new Date(data.timeZero);
    db.collection("data").insert(data, {w:1}, function(err, result){
        if(err){
            console.error('Data storage exception: ', err);
            res.send({error:'Error storing data'});
        }
        else{
            res.end();
        }
    });
});

function getDateString(date){
    var dayMap = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
    var monthMap = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];

    return dayMap[date.getDay()] + ' ' + monthMap[date.getMonth()] + ' ' + date.getDate() + ' ' + date.getFullYear() + ' ' + date.toTimeString();
}

function generateOptionsCols(d, count){

    var cols = new columnizer();

    cols.addColumn([
        'Experiment:', 
        'Observers:', 
        'Time zero:', 
        'Time since 1/1/70 (s):', 
        '"Location (latitude, longitude):"', 
        'Location near:',
        'Interval between ratings (s):',
        'Maximum stimulus duration (s):',
        'Experiment duration after end of stimulus (s):',
        'Recorded duration (s):',
        'Feedback barbell:',
        'Feedback bar:',
        'Feedback bar color varies:',
        'Feedback number:',
        'Feedback tone:',
        'Feedback ticks:',
        'Include practice in reference:',
        'Knockout:',
        'Enable name condition:',
        'Enable sad mood condition:',
        'Duration of mood induction (s):',
        'Enable music selection:',
        'Music title:',
        'Music artist:',
        'Music album:',
        'Music duration (s):']);

    cols.addColumn([
        d.experiment,
        count,
        getDateString(d.timeZero),
        (d.timeZero.getTime() / 1000).toFixed(2),
        '"' + (d.location.lat || 0) + ',' + (d.location.long || 0) + '"',
        '"' + d.location.near + '"',
        d.options.ratingInterval,
        d.options.duration,
        d.options.postStimulusDuration,
        d.actualDuration,
        d.options.feedback.barbell,
        d.options.feedback.range,
        d.options.feedback.numeric,
        d.options.feedback.auditory,
        d.options.feedback.tactile,
        d.options.feedback.barVaries,
        d.options.postInMedian,
        d.knockout,
        d.options.nameSelect,
        d.options.moodSelect,
        d.options.moodDuration,
        d.options.musicSelect,
        d.songName,
        d.songArtist,
        d.songAlbum,
        d.songDuration
    ]);

    return cols;
}


app.get('/expcount', function(req, res) {
    var range = +req.query.r,
        midTime = +req.query.t;

    if(isNaN(range) || isNaN(midTime) || range < 60000 || range > 3600000 || (midTime - range) > (new Date()).getTime()) {
        return res.send({error:'Time range out of bounds.'});
    }
    
    var sTime = new Date(midTime - range),
        eTime = new Date(midTime + range),
        data = db.collection("data");

    data.find({settings_id: req.query.id, timeZero: {$gte: sTime, $lt: eTime}, optionsMode: 'server'}).toArray(function(err, docs){
        if(err){
            console.error('Data retrieval exception: ', err);
            return res.send({error:'Error fetching data.'});
        }

        return res.send({count: docs.length});
    });
});


app.get('/expdata', function(req, res) {
    var range = +req.query.r,
        midTime = +req.query.t;

    if(isNaN(range) || isNaN(midTime) || range < 60000 || range > 3600000 || (midTime - range) > (new Date()).getTime()) {
        return res.send({error:'Time range out of bounds.'});
    }
    
    var sTime = new Date(midTime - range),
        eTime = new Date(midTime + range),
        data = db.collection("data");

    data.find({settings_id: req.query.id, timeZero: {$gte: sTime, $lt: eTime}, optionsMode: 'server'}).toArray(function(err, docs){
        if(err){
            console.error('Data retrieval exception: ', err);
            return res.send({error:'Error fetching data.'});
        }

        if(docs.length == 0){
            return res.send({error: 'No trials on record.'})
        }

        docs.sort(function(a,b){
            return b.feltPleasure - a.feltPleasure;
        });

        var medianTrial, medianZero = Infinity, maxDuration = -1, maxDurTrial, cols;

        for(var i = 0; i < docs.length; i++){
            var d = docs[i];
            if(d.actualDuration > maxDuration){
                maxDuration = d.actualDuration;
                maxDurTrial = d;
            }

            if(d.timeZero < medianZero){
                medianZero = d.timeZero;
                medianTrial = d;
            }

            //timeZeros.push(d.timeZero.getTime());
        }

/*        var medianZero = Math.round(findMedian(timeZeros)),
            medianTrial = maxDurTrial;

        for(var i = 0; i<docs.length; i++){
            if(docs[i].timeZero.getTime() == medianZero){
                medianTrial = docs[i];
                break;
            }
        }*/

        cols = generateOptionsCols(medianTrial, docs.length);
        var minTimeZero = Infinity, maxTimeZero = -Infinity;

        for(var i = 0; i < docs.length; i++){
            var timeDiff = Math.round(docs[i].timeZero.getTime() - medianZero);
            
            if(timeDiff < minTimeZero){
                minTimeZero = timeDiff;
            }

            if(timeDiff > maxTimeZero){
                maxTimeZero = timeDiff;
            }
        }
        minTimeZero = Math.ceil(minTimeZero/1000);
        maxTimeZero = Math.ceil(maxTimeZero/1000);

        var times = ['Time(s)'];
        var maxTime = maxTimeZero + maxDuration;
        for(var i = minTimeZero; i < maxTime; i+= medianTrial.options.ratingInterval){
            times.push(i);
        }
        cols.addColumn(times);
        var numTimes = Math.floor((maxTime - minTimeZero + 1) / medianTrial.options.ratingInterval);
        var allValues = new Array(numTimes), yesValues = new Array(numTimes), noValues = new Array(numTimes);

        for(var i = 0; i<numTimes; i++){
            allValues[i] = [];
            yesValues[i] = [];
            noValues[i] = [];
        }

        for(var i = 0; i<docs.length; i++){
            var d = docs[i];
            var ratings = d.ratings,
                tZero = Math.round((d.timeZero.getTime() - medianZero)/1000),
                tZeroDiff = (tZero - minTimeZero) / medianTrial.options.ratingInterval;

            var rat = [ratings[0]],
                k = 0, c = medianTrial.options.ratingInterval;

            while(k < ratings.length - 1){
                while(d.time[k+1] <= c){
                    k++;
                }

                if(k >= ratings.length - 1) break;

                rat.push( (+ratings[k] + (ratings[k+1] - ratings[k])*((c - d.time[k])/(d.time[k+1] - d.time[k]))).toFixed(1) );
                c += medianTrial.options.ratingInterval;
            }

            for(var j = 0; j<tZeroDiff; j++){
                rat.unshift('');
            }

            rat.unshift(d.feltPleasure + ' ' + d.name);
            cols.addColumn(rat);

            for(var j = 1; j<rat.length; j++){
                if(rat[j] !== ''){
                    var r = parseFloat(rat[j]);
                    allValues[j-1].push(r);
                    if(d.feltPleasure == 3 || d.feltPleasure == 2){
                        yesValues[j-1].push(r);
                    }
                    else{
                        noValues[j-1].push(r);
                    }
                }
            }
        }

        var allMeans = ['Mean'], allSE = ['S.E.'],
            yesMeans = ['Yes Mean'],  yesSE = ['Yes S.E.'],
            noMeans = ['No Mean'], noSE = ['No S.E.'];

        for(var i = 0; i<numTimes; i++){
            var a = findAverage(allValues[i]);
            allMeans.push(isNaN(a.mean) ? '' : a.mean.toFixed(1));
            allSE.push((isNaN(a.deviation) || a.deviation == 0) ? '' : (a.deviation / allValues[i].length).toFixed(1));

            a = findAverage(yesValues[i]);
            yesMeans.push(isNaN(a.mean) ? '' : a.mean.toFixed(1));
            yesSE.push((isNaN(a.deviation) || a.deviation == 0) ? '' : (a.deviation / yesValues[i].length).toFixed(1));

            a = findAverage(noValues[i]);
            noMeans.push(isNaN(a.mean) ? '' : a.mean.toFixed(1));
            noSE.push((isNaN(a.deviation) || a.deviation == 0) ? '' : (a.deviation / noValues[i].length).toFixed(1));
        }

        cols.addColumn(times);
        cols.addColumn(allMeans);
        cols.addColumn(allSE);

        cols.addColumn(times);
        cols.addColumn(yesMeans);
        cols.addColumn(yesSE);
        cols.addColumn(noMeans);
        cols.addColumn(noSE);

        res.send({data: cols.generate().replace(/ /g,"%20")});
    });
});

MongoClient.connect('mongodb://127.0.0.1:27017/emotion-data', function(err, _db) {
    if(err) console.error(err);
    db = _db;
    var server = app.listen(80, function() {
        console.log('Listening on port %d', server.address().port);
    });
});
