const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const User = require("../models/user.model");
const User_DB = [];
require("dotenv").config();

exports.register = (req, res) => {
  var newUser = new User(req.body.username, bcrypt.hashSync(req.body.password, 10));
  User_DB.push(newUser);
  return res.status(201).json({
    msg: "New User created !",
  });
};

exports.login = (req, res) => {
  const { username, password } = req.body;

  const user = User_DB.find((u) => u.username === username && bcrypt.compareSync(password, u.password));
  if (user) {
    const accessToken = jwt.sign({ username: user.username, exp: Math.floor(Date.now() / 1000) + 120 }, process.env.ACCESS_JWT_KEY);
    return res.status(200).json({ message: "You are now connected !token : " + accessToken });
  } else {
    return res.status(401).json({ message: "Invalid credentials" });
  }
};

exports.authenticate = (req, res) => {
  let token = req.headers["authorization"];

  // TO-DO : Le token est renvoyé avec le préfix « Bearer », stockez dans une variable seulement le token.
  //TO-DO : Faites les vérifications nécessaires.

  if (!token) {
    return res.status(401).json({ message: "No token provided!" });
  }
  const tokenParts = token.split(" ");
  if (tokenParts.length !== 2 || tokenParts[0] !== "Bearer") {
    return res.status(401).json({ message: "Invalid token format!" });
  }

  /* 
     Autres méthodes :
     if (token && token.startsWith("Bearer "))
        tokenDecrypted = token.slice(7, token.length);
    */

  let tokenDecrypted = tokenParts[1];

  jwt.verify(tokenDecrypted, process.env.ACCESS_JWT_KEY, (err, decoded) => {
    // TO-DO : Vérification si l’utilisateur décodé existe
    // TO-DO : Renvoyer une réponse adaptée en fonction de son état
    if (err) {
      return res.status(401).json({ message: "Unauthorized!" });
    } else {
      const verify = User_DB.find((u) => u.username === decoded.username);
      if (verify) {
        return res.status(200).json({ message: "You can access !" });
      } else {
        return res.status(404).json({ message: "Permission rejected !" });
      }
    }
  });
};
