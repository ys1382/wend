var port = parseInt(process.env.PORT) || 8080;

function authenticate(whom, success, reason) {
	var data = {event:'auth', success:success, reason:reason}
	this.crypt.send(data, whom);
}

function accept(whom, reason) {
	authenticate(whom, true, reason);
}

function reject(whom, reason) {
	authenticate(whom, false, reason);
}

// handlers

function salted(data) {
	var who = data.from;
	console.log('salt user=' + who);
	var s = this;

	PersonModel.find({name:who}, function (err, docs) {
		if (err)
			reject(who, err);
		else if (!docs.length)
			reject(who, 'salt: user ' + who + ' does not exist');
		else if (!docs[0].salt)
			reject(who, 'salt: user ' + who + ' is missing salt');
		else try{
			s.crypt.send({event:'salt', salt:JSON.parse(docs[0].salt)}, who);
		} catch(err) {
			reject(who, 'salt: ' + err.message);
		}
	});
}

function signuped(data) {
	var who = data.from;
	console.log('signup user=' + who + ' hashed =' + typeof(data.hashed));
	PersonModel.find({name:who}, function (err, docs) {
		if (err)
			reject(who, err);
		else if (docs.length)
			reject(who, 'signup: user ' + who + ' exists');
		else if (!data.hashed || !data.salt)
			reject(who, 'signup: missing data');
		else {
			var person = new PersonModel();
			person.name = who;
			console.log('store hash into db: ' + typeof(data.hashed));
			person.hashed = JSON.stringify(data.hashed);
			person.salt = JSON.stringify(data.salt);
			person.save(function (err) {
				if (!err)// console.log('saved 1');
					accept(who, 'signup: user ' + who + ' created');
				else
					reject(who, err);
			});
		}
	});
};

Array.prototype.compare = function(testArr) {
    if (this.length != testArr.length) return false;
    for (var i = 0; i < testArr.length; i++) {
        if (this[i].compare) { 
            if (!this[i].compare(testArr[i])) return false;
        }
        if (this[i] !== testArr[i]) return false;
    }
    return true;
}

function signined(data) {
	var who = data.from;
	console.log('signin user=' + who + ' hashed=' + typeof(data.hashed));
	PersonModel.find({name:who}, function (err, docs) {
		if (err)
			reject(err);
		else if (!docs.length)
			reject(who, 'signin: user ' + who + ' does not exist');
		else if (!docs[0].hashed)
			reject(who, 'signin: user ' + who + ' is missing hashed');
		else {
			try {
				var hashedFromDB = JSON.parse(docs[0].hashed);
				console.log('hash from db: ' + hashedFromDB);
				var hashed = crypt.salthash(hashedFromDB, data.salt).hashed;
				
				if (!hashed.compare(data.hashed))
					reject(who, 'signin: user ' + who + ' password mismatch: ' + data.hashed + ' != ' + hashed);
				else
					accept(who, 'welcome back');
			} catch (err) {
				reject(who, 'signin: user ' + who + ' error:' + err.message);
			}
		}
	});
}

// setup

var mongoose = require('mongoose'),
			   Schema = mongoose.Schema,
			   ObjectId = Schema.ObjectId;
mongoose.connect(process.env.MONGOLAB_URI || 'mongodb://localhost/my_database')


var PersonSchema = new Schema({
	uid		: String,
	hashed	: String,
	salt	: String,
	name	: String,
	pubkey  : String
});
var PersonModel = mongoose.model('Person', PersonSchema);

var PostingSchema = new Schema({
	from	: ObjectId,
	to		: ObjectId,
	body	: String
});
var PostingModel = mongoose.model('Posting', PostingSchema);

var express = require('express');
var app = express.createServer();
app.use(express.static(__dirname));
app.listen(port);
console.log('listening on port ' + port);

var handler = function(data) {
	var handler = {salt:salted, signup:signuped, signin:signined} [data.event];
	handler && handler(data);
}

var Crypt = require('./crypt');
crypt = new Crypt({handle:handler}, 'server', app);
