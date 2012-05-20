(function(){

	/////// UI

	function setPlaceholder(input, text) {
		input.val(text);
		input.addClass('placeholder');
		input.attr('placeholder', text);
		input.css({color:'#bbbbbb'});
		input.focus(function(){
			var input = $(this);
			//console.log('val='+input.val+', ph='+input.attr('placeholder'));
			if (input.val() == input.attr('placeholder')) {
				input.val('');
			    input.removeClass('placeholder');
			} else
				$(this).css({color:'#000000'});
			$(this).css("background-color","#FFFFCC");
		}).blur(function() {
			var input = $(this);
			if (input.val() == '' || input.val() == input.attr('placeholder')) {
				input.addClass('placeholder');
				input.attr('placeholder', text);
				input.val(input.placeholder);
			}
			$(this).css("background-color","#FFFFFF");
		}).blur();
	}

	function setHtml(hint0, hint1, button0, button1, click0, click1) {
		setPlaceholder($('#input0'), hint0);
		setPlaceholder($('#input1'), hint1);
		$("#button0").html(button0);
		$("#button1").html(button1);
		$("#button0").unbind('click');
		$("#button0").click(function(){ click0(); });
		$("#button1").unbind('click');
		$("#button1").click(function(){ click1(); });
	}

	function authenticate() {
		if (localStorage.credentials) {
			var cobj = JSON.parse(localStorage.credentials);
			if (cobj.username && cobj.username.length && cobj.password && cobj.password.length) {
				this.credentials = cobj;
				signin(cobj);
				return;
			}
		}
		showAuthenticate();
	}
	
	function missive() {
		var to = $("#input0").val();
		var text = $("#input1").val();
		addToTranscript(client.crypt.id, to, text);
		client.crypt.send({event:'text', text:text}, to);
	}

	function showAuthenticate() {
		setHtml('username', 'password', 'signin', 'signup', signin, signup);
	}

	function showChat() {
		setHtml('to', 'message', 'send', 'logout', missive, logout);
	}

	function logout() {
		localStorage.removeItem('credentials');
		authenticate();
	}

	function signin(credentials) {
		console.log('signin ' + JSON.stringify(credentials));
		client.credentials = credentials || inputs();
		$.extend(client, client.credentials);
		client.greet('salt', {username:client.credentials.username});
	}

	function inputs() {
		return { username:$("#input0").val(), password:$("#input1").val() };
	}

	function signup() {
		var credentials = inputs();
		console.log('p = ' + credentials.password);
		var hashed = client.crypt.salthash(credentials.password);
		client.greet('signup', $.extend({username:credentials.username}, hashed));
	};

	/////// Client

	Client = function() {
		this.crypt = new Crypt(this);
		this.crypt.connect(window.location);
	}

	Client.prototype.salted = function(data) {
		console.log('salted ' + data.salt);
		credentials = this.credentials || inputs();
		console.log('\tcredentials = ' + JSON.stringify(this.credentials));
		var hashed = client.crypt.salthash(credentials.password, data.salt);
		console.log('hashed = ' + JSON.stringify(hashed))
		var hashedAgain = client.crypt.salthash(hashed.hashed);
		client.greet('signin', $.extend({username:credentials.username}, hashedAgain));
	}

	Client.prototype.greet = function(verb, credentials) {
		this.crypt.setId(credentials.username);
		var msg = $.extend(credentials, {event:verb});
		this.crypt.send(msg, 'server');
	}

	Client.prototype.authed = function(data) {
		console.log('authenticate -- ' + data.success);
		var i = inputs();
		if (data.success) {
			if  (i.username.length)
				localStorage.credentials = JSON.stringify(i);
			showChat();
		}
		else
			showAuthenticate();
	}

	Client.prototype.texted = function(data) {
		console.log('texted -- ' + data.text);
		addToTranscript(data.from, this.crypt.id, data.text);
	}

	function addToTranscript(from, to, text) {
		var time = new Date()
		var h = time.getHours();
		var m = time.getMinutes();
		var when = h +':'+ (m < 10 ? '0':'') + m;
		$('#transcript').prepend('<p>'+ when +' '+ from +'=>'+ to +' -- '+ text +'</p>');
	}

	Client.prototype.handle = function(data) {
		if (data.event == 'salt')		this.salted(data);
		else if (data.event == 'auth')	this.authed(data);
		else if (data.event == 'text')	this.texted(data);
	}

	/////// main

	var client;

	$(document).ready(function() {
		client = new Client();
		authenticate();
	});

})();
