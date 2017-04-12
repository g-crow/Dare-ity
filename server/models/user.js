const bcrypt = require('bcrypt');
const config = require('../../config');
const db = require('../../db');
const jwt = require('jsonwebtoken');

class User{
	constructor(name, password, email, is_npo){
		this.name = name;
		this.password = password;
		this.email = email;
		this.is_npo = is_npo
	}

	save(callback){
		if (!this.name || !this.password){
			callback(new Error('No Name or password provided'))
		} else {
			const hashed_password = ''
			bcrypt.hash(this.password, config.saltRounds, (hashErr, hashed_password) => {
				if (!hashErr){
					const queryString = `INSERT INTO dareity_user (name, password, email, is_npo) 
          VALUES ($1, $2, $3, $4) RETURNING *`
					db.query(queryString, [this.name, hashed_password, this.email, this.is_npo], callback)
				} else {
					callback(hashErr)
				}
			})
		}
	}
}

User.authenticate = function(name, password, callback){
    let queryString = `SELECT name, id, is_npo, password FROM dareity_user WHERE name = $1`
    db.query(queryString, [name], function(err, result) {
      const user = result.rows[0]
      if (err) throw err;
        if (!user) {
          callback('Authentication failed. User not found.')
        } else {
          bcrypt.compare(password, user.password, function(err, passwordValid){
            if (passwordValid == false) {
              callback('Authentication failed. Wrong password.');
            } else {
              var token = jwt.sign(user, config.secret, {
                expiresIn: "1d" // expires in 24 hours
              }); 
              callback(null, token)
            }
          });
        }
    }
  )
}

User.requireLogin = function(req, res, next) {
  var token = req.body.token || req.query.token || req.headers['x-access-token'];
  if (token) {
    jwt.verify(token, config.secret, function(err, decoded) {
      if (err) {
        return res.json({ success: false, message: 'Failed to authenticate token.' });
      } else {
        decoded.id = req.body.npo_creator;
        req.decoded = decoded;
        next();
      }
    });

  } else {
    return res.status(403).send({
        success: false,
        message: 'No token provided.'
    });
  }
};

User.fetchUser = function(query, callback) {
  db.query('SELECT name, email FROM dareity_user WHERE name=$1 OR email=$2', [query.name, query.email], function(err, result){
    const user = result.rows[0]
    if (err){
      callback(err.message)
    } else if (user) {
      callback(null, user)
    } else {
      callback('No user found.')
    }
  })
};

User.updateUser = function(query, id, callback) {
  let columns= ''
  let columnArr = []
  let colCounter = 0
  if (query.is_npo) {
    colCounter++
    columnArr.push(query.is_npo)
    columns += `is_npo = $${colCounter}, `
  }
  if (query.email) {
    colCounter++
    columnArr.push(query.email)
    columns += `email = $${colCounter}, `
  }
  columns = columns.replace(/, $/, '')
  colCounter++
  columnArr.push(id)
  const queryString = `UPDATE dareity_user SET ${columns} WHERE id = $${colCounter} RETURNING *`
  db.query(queryString, columnArr, function(err, result) {
    if (err) {
      callback(null, err.message)
    } else {
      callback(null, result)
    }
  })
}

module.exports = User
