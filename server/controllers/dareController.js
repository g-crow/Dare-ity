const Dare = require ('../models/dare');

const createDare = function(req, res){
	const {
			title,
			description,
			npo_creator,
			expiration,
			pledge_threshold,
			video_path
		  } = req.body;
	var dare = new Dare(title, description, npo_creator, expiration, pledge_threshold, video_path)
    dare.save((err, dare) => err ? res.status(500).json(err) : res.json(dare))
}

const fetchDare = function(req, res) {
  const { query } = req.body;
  Dare.fetchDare(query, (err, result) => {
    if (err) {
      res.status(400).json({success: false, message: err})
    } else {
      res.json({
                success: true,
                result: result
              });
   }
 })
}

const updateDare = function(req, res) {
 const id = req.body.id;
 const query = req.body;
 Dare.updateDare(query, id, (err, result) => {
   if (err) {
     res.status(400).json({success: false, message: err})
   } else {
     res.json({
               success: true,
               result: result
             });
   }
 })
}

const setDare = function(req, res) {
  const query = req.body;
  Dare.setDare(query, function(err, result) {
    if (err) {
      res.status(400).json({ success: false, message: err})
    } else {
      res.json({
                success: true,
                result: result
              });
    }
  })
}

const fetchUserDare = function(req, res) {
  const { query } = req.body
  Dare.fetchUserDare(query, function(err, result) {
    if (err) {
      res.status(400).json({success: false, message: err})
    } else {
      res.json({ success: true, result: result})
    }
  })
}

const updateUserDare = function(req, res) {
  const query = req.body
  Dare.updateUserDare(query, function(err, result) {
    if (err) {
      res.status(400).json({success: false, message: err})
    } else {
      res.json({ success: true, result: result})
    }
  })
}

module.exports = { createDare, fetchDare, updateDare, setDare, fetchUserDare, updateUserDare };
