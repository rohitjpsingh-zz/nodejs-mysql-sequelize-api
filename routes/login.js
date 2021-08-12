const express = require("express");
const db = require("../models/index");
const bcrypt = require("bcrypt");
const router = express.Router();
const passport = require("passport");
const jwt = require("jsonwebtoken");
const { User } = db;
const saltRounds = 10;


// Register API
router.post("/register", (req, res) => {
  console.log("====================================");
  console.log("req.body:", req.body);
  console.log("====================================");
  if (req.body.username && req.body.password) {
    User.findOne({ where: { email: req.body.username }, raw: false })
      .then((user) => {
        if (user) {
          res.status(401).json({ message: "Username already exists" });
        } else {
          const hash = bcrypt.hashSync(req.body.password, saltRounds);
          console.log("hash:",hash);
          User.create({
            email: req.body.username,
            password: hash
          })
            .then((userNew) => {
              const payload = { id: userNew.id };
              const token = jwt.sign(payload, process.env.JWT_SECRET);
              res.json({ token });
            })
            .catch(() => {
              res.status(401).json({ message: "Error Creating User" });
            });
        }
      })
      .catch((err) => {
        res.status(401).json({ message: err });
      });
  } else {
    res.status(401).json({ message: "Insufficient Information to register" });
  }
});

// Login API
router.post("/login", (req, res, done) => {
  passport.authenticate("clientLocal", (err, user, info) => {
    if (err) {
      return done(err); // will generate a 500 error
    }
    // Generate a JSON response reflecting authentication status
    if (!user) {
      return res.status(401).json({ success: false, info });
    }
    req.login(user, (loginErr) => {
      if (loginErr) {
        return done(loginErr);
      }
      const payload = { id: req.user.id };
      const token = jwt.sign(payload, process.env.JWT_SECRET);
      return res.json({ token });
    });
  })(req, res, done);
});

// Get User API
router.get("/:id",passport.authenticate(["clientJwt"], { session: false }),
  (req, res) => {
    const clientId = req.params.id;
    return User.findOne({
      where: {
        id: clientId,
      },
      raw: false,
    }).then((result) => {
      res.send(result);
    });
  }
);

module.exports = router;
