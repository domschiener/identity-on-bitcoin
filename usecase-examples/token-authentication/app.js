var express = require('express');
var request = require('request');
var bodyParser = require('body-parser')
var fs = require('fs');
var openpgp = require('openpgp');
 
var app = express();
app.use(express.static(__dirname));
app.use(bodyParser.json());


//AUTHENTICATION: GETS IDENTITIES
app.get('/auth', function(req, res){
	fs.readFile('./privkey.asc', 'utf8', function (err,data) {
		if (err) {
			return console.log(err);
		}
		gen_certificate(data);
	});

	function gen_certificate(privkey_str) {
		var privkey = openpgp.key.readArmored(privkey_str).keys[0];
		var passphrase = 'this is the most secret password a super secret website can have';
		var pubkey = privkey.toPublic().armor();
		var date = new Date();

		var certificate = {
			'pubkey': pubkey,
			'info': {
				'company':'Simple Signup LLC',
				'address':'Phanstasie Street 123, London N54 F32, United Kingdom',
				'contact-mail':'Signup Example <signup@example.com>',
				'website':'www.example.com',
				'trust-score':'88',
				'date': date
			},
		};

		//signing the info for verification
		privkey.decrypt(passphrase);
	    openpgp.signClearMessage(privkey, String(certificate['info'])).then(function(signed)  {
	        certificate['signature'] = signed;
	        sendcert(certificate);
	    });
	};

	function sendcert(certificate) {
		request.post(
		    'http://127.0.0.1:5000/api/v1.0/auth',
		    {json: true, body:certificate},
		    function (error, response, body) {
			    res.send(body);
			}
		);
	}
});


//POST IDENTITY: GETS ATTRIBUTES
app.post('/identity', function(req, res){
	var identity = req.body.name
	request.post(
	    'http://127.0.0.1:5000/api/v1.0/attributes',
	    {json: true, body:identity},
	    function (error, response, attributes) {
		    res.send(attributes);
		}
	);
});

//POST ATTRIBUTES: GET decrypted attributes
app.post('/attributes', function(req, res){
	var attributes = req.body.name
	request.post(
	    'http://127.0.0.1:5000/api/v1.0/decrypt',
	    {json: true, body:attributes},
	    function (error, response, decrypted) {
		    res.send(decrypted);
		}
	);
});


//START SERVERS
app.listen(8080, function() {
  console.log('Server running at http://127.0.0.1:8080/');
});