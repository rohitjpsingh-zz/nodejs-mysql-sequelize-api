// Passport
const passport = require("passport");
const bcrypt = require("bcrypt");
const LocalStrategy = require("passport-local").Strategy;
const JwtStrategy = require("passport-jwt").Strategy;
const { ExtractJwt } = require("passport-jwt");
const db = require("./models/index");
const { User } = db;

passport.serializeUser(function (user, done) {
  done(null, user);
});

passport.deserializeUser(function (user, done) {
  done(null, user);
});

// Passport authenticaton
passport.use(
  "clientLocal",
  new LocalStrategy((username, password, done) => {
    return User.findOne({ where: { email: username }, raw: false })
      .then((user) => {
        if (!user) {
          return done(null, false, { message: "Incorrect username." });
        }
        if (!bcrypt.compareSync(password, user.password)) {
          return done(null, false, { message: "Incorrect password." });
        }
        return done(null, user);
      })
      .catch((err) => done(err));
  })
);

// Passport JWT Auth
passport.use(
  "clientJwt",
  new JwtStrategy(
    {
      jwtFromRequest: ExtractJwt.fromAuthHeaderWithScheme("JWT"),
      secretOrKey: process.env.JWT_SECRET,
    },
    (jwtPayload, done) => {
      return User.findOne({ where: { id: jwtPayload.id }, raw: false })
        .then((user) => {
          if (!user) {
            return done(null, false, { message: "Incorrect user." });
          }
          return done(null, user);
        })
        .catch((err) => done(err));
    }
  )
);
