const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const User = require("../models/user.model");
const User_DB = [];

exports.register = (req, res) => {
  var newUser = new User(req.body.username, bcrypt.hashSync(req.body.password, 10));
  User_DB.push(newUser);
  return res.status(201).json({
    msg: "New User created ! Welcome " + req.body.username,
  });
};
