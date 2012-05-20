if (typeof require != 'undefined') {
	sjcl = require('./sjcl');
}

function Crypt(listener, id, port) {
	this.listener = listener;
	this.id = id;

	this.uri2socket = {};
	this.socketList = [];
	this.peers = {};
	this.queue = {};

	seedRNG();
	this.keys = sjcl.ecc.elGamal.generateKeys(384, 10);
	this.pubstr = JSON.stringify(this.keys.pub.serialize());

	if (port) { // then listen
		var io = require('socket.io').listen(port);
		io.set("log level", 1);
		io.configure(function () { 
			io.set("transports", ["xhr-polling"]); 
			io.set("polling duration", 10); 
		});
		io.sockets.on('connection', function (socket) {
			console.log('connected')
			crypt.addSocket(socket);
		});
		this.io = io;
	}
}

Crypt.prototype.setId = function(id) {
	console.log('setId to ' + id);
	this.id = id;
	for (peer in this.peers)
		this.sendPublicKey(peer, this.peers[peer].via);
}

Crypt.prototype.connect = function(uri) {
	if (this.uri2socket[uri])
		this.listener.connected(uri);
	else {
		socket = io.connect(uri);
		socket.on('connect', this.addSocket.bind(this, socket, uri));
	}
}

Crypt.prototype.addSocket = function(socket, uri) {
	console.log('addSocket ' );
	if (uri)
		this.uri2socket[uri] = socket.id;
	socket.on('message', this.handle.bind(this, socket));
	socket.send(this.pubstr);
	this.socketList.push(socket);
}

function setAttributes(dst, src) {
	for (key in src)
		dst[key] = src[key];
}

Crypt.prototype.receivedPublicKey = function(socket, datastr, from) {
	console.log('receivedPublicKey' + (from ? ' from ' + from : ''));
	var pubjson = JSON.parse(datastr);
	var point = sjcl.ecc.curves['c'+pubjson.curve].fromBits(pubjson.point)
	var pubkey = new sjcl.ecc.elGamal.publicKey(pubjson.curve, point.curve, point);
	var symkey =  this.keys.sec.dh(pubkey);

	if (from) {
		this.peers[from] = {socketId:socket.id};
		setAttributes(this.peers[from],{pub:pubkey, sym:symkey, via:socket});
		var q = this.queue[from];
		for (var i in q)
			this.send(q[i], from);
		delete this.queue[from];
	} else {
		console.log('socket secured ');
		socket.symkey = symkey;
		for (var to in this.queue)
			this.sendPublicKey(to, socket);
	}
}

Crypt.prototype.route = function(data) {
	var sid = this.peers[data.to].socketId;
	var outsocket = this.io.sockets.socket(sid);
	if (!outsocket)
		console.log('no socket for ' + data.to);
	else {
		console.log('route to ' + data.to);
		this.sendOnSocket(outsocket, data);
	}
}

Crypt.prototype.handle = function(socket, socketData) {
	if (!socket.symkey) {
		this.receivedPublicKey(socket, socketData);
		return;
	}
	var peerCipherData = sjcl.decrypt(socket.symkey, socketData);
	var data = JSON.parse(peerCipherData);
	var from = data.from;
	console.log('recv: data.to=' + data.to +', from=' + from);

	if (data.to != this.id)
		this.route(data);
	else if (data.pk) { // pk for me
		this.receivedPublicKey(socket, data.pk, from);
		if (!data.isResponse)
			this.sendPublicKey(from, socket, true);
	} else if (this.peers[from]) {
		var cleardata = sjcl.decrypt(this.peers[from].sym, data.data);
		console.log('decrypted: ' + cleardata);
		var parsed = JSON.parse(cleardata);
		parsed.from = from;
		this.listener.handle(parsed);
	} else
		console.log("I don't have a pk for " + from);
}

Crypt.prototype.sendPublicKey = function(to, socket, isResponse) { // sent to peer
	console.log('sendPublicKey to ' + to);
	var pk = JSON.stringify(this.keys.pub.serialize());
	var data = {event:'pubkey', from:this.id, isResponse:isResponse, pk:pk, to:to};
	this.sendOnSocket(socket, data);
}

Crypt.prototype.send = function(data, to) {
	console.log('send to ' + to +': '+ JSON.stringify(data));

	var peer = this.peers[to];
	if (peer && peer.pub) {

		var cleardata = JSON.stringify(data);
		//console.log('    shall send ' + cleardata);
		var cipherdata = sjcl.encrypt(peer.sym, cleardata);
		data = {to:to, from:this.id, data:cipherdata};
		this.sendOnSocket(peer.via, data);

	} else if (!peer || !peer.pubd) {

		console.log('first send pubkey to ' + to);
		if (!this.queue[to])
			this.queue[to] = [];
		this.queue[to].push(data);

		for (var i=0; i<this.socketList.length; i++) { // todo: don't flood
			var socket = this.socketList[i];
			this.sendPublicKey(to, socket);
		}
	}
}

Crypt.prototype.sendOnSocket = function(socket, data) {
	var datastr = JSON.stringify(data);
	if (!socket.symkey) {
		console.log('no symkey for socket');
		return;
	}
	data.from = this.id;
//	console.log('encrypt and send ' + datastr);
	var cipherdata = sjcl.encrypt(socket.symkey, datastr);
	socket.send(cipherdata);
}

Crypt.prototype.salthash = function (password, salt) {
//	console.log('salthash ' + typeof(salt));
	salt = salt || sjcl.random.randomWords(8);
//	salt = salt ? sjcl.codec.hex.toBits(salt) : sjcl.random.randomWords(8);
	console.log('salthash: ' + typeof(password) + ', ' + typeof(salt) + ' -- ' + password +' and '+ salt);
	var	count = 2048;
	var hpw = sjcl.misc.pbkdf2(password, salt, count);
	return {hashed:hpw, salt:salt};
}

function seedRNG() {
	sjcl.random.setDefaultParanoia(0);
	for (var i=0; i<1024; i++) {
		var r = Math.floor((Math.random()*100)+1);
	    sjcl.random.addEntropy(r, 1);
	}
}

if (typeof module != 'undefined') {
	module.exports = Crypt;
}
