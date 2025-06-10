const authController = require("../controllers/auth.controller");

module.exports = function (app) {
  app.post("/register", authController.register);
  app.post("/login", authController.login);
  app.post("/authenticate", authController.authenticate);
};
