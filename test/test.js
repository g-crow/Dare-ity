var server = require('../server')
var chai = require('chai')
var chaiHttp = require('chai-http');
var pg = require('pg');
const user = require('../server/models/user');
const userController = require('../server/controllers/userController')
chai.use(chaiHttp);

var should = chai.should();
var userId;
var uniqueName = 'smeary' + Date.now()
var uniqueDare = 'plunge' + Date.now()

describe('POST /api/create_user', function() {
	it('should return NPO user object', function(done){
		chai.request(server)
		.post('/api/create_user')
     	.send({'name': uniqueName, 'password': 'abc', 'email': "bob.abc@gmail.com", 'is_npo': true})
     	.end(function(err,res){
         res.body.should.be.a('object');
         res.body.should.have.property('name');
         res.body.should.have.property('password');
         res.body.should.have.property('email');
         res.body.should.have.property('is_npo');
         res.body.name.should.equal(uniqueName);
         //res.body.password.should.equal(hashed_password);
         res.body.email.should.equal('bob.abc@gmail.com');
         res.body.is_npo.should.equal(true);
         userId = res.body.id;
         done();
     	})
    });
});

describe('POST /api/authenticate', function() {
	it('should return token', function(done){
		chai.request(server)
		.post('/api/authenticate')
		.send({'name': uniqueName, 'password': 'abc'})
		.end(function(err,res){
			res.body.should.be.a('object');
			res.body.should.have.property('success');
			res.body.should.have.property('message');
			res.body.should.have.property('token');
			res.body.success.should.equal(true);
			res.body.message.should.equal('Please have a token!');
			done();
		})
	});
});

const getTokenForTest = function(server, callback){
  chai.request(server)
      .post('/api/authenticate') 
	  .send({'name': uniqueName, 'password': "abc"})
      .end((err, res) => {
      	callback(null, JSON.parse(res.res.text).token)
  	})
}

describe('POST /api/create_dare', function() {
 	it('should return dare object', function(done) {
 		getTokenForTest(server, (err, token)=>{
         chai.request(server) 
         .post('/api/create_dare')
         .send({'npo_creator': userId, 'dare_title': uniqueDare, 'token': token, 'dare_description': "interpret as you'd like"})
         .end(function(err,res){
             res.body.should.be.a('object');
             res.body.should.have.property('title');
             res.body.should.have.property('description');
             res.body.title.should.equal(uniqueDare);
             res.body.description.should.equal("interpret as you'd like");
             done();
         })
 	    });
 	})
});



describe('POST /api/create_dare', function() {
	 it('blank fields should return message', function() {
	 	getTokenForTest(server, (err, token)=>{
		     chai.request(server) 
		     .post('/api/create_dare')
		     .send({'dare_title': undefined, 'dare_description': undefined})
		     .end(function(err,res){
		         res.body.should.be.a('object');
		         res.body.json.should.equal(JSON.stringify("Please set all required parameters."));
		         done();
		     })
	 	});
	 })
});


//UNFINISHED TEST

// describe('POST /api/delete_record', function() {
//  it('should delete record', function(done) {
//      requireLogin(server, (err, token) =>{
//          chai.request(server) 
//          .post('/api/delete_record')
//          .send({'id': 11, 'token': token, 'table_name': "dare"})
//          .end(function(err,res){
//          	 console.log('response', res.res.text)
//              res.body.should.be.a('object');
//              res.body.should.have.property('command');
//              res.body.should.have.property('rowCount');
//              res.body.command.should.equal('DELETE');
//              res.body.rowCount.should.equal(1);
//              done();
//          })
//      }); 
//  });
// });