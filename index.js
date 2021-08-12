const express = require('express');
const bodyParser = require('body-parser')
const app = express();
const path = require('path');
const cors = require('cors');
const logger = require('morgan');
const env = require('dotenv').config();
const routes = require('./routes');
const models = require("./models");
const passport = require("passport");

const PORT =  process.env.PORT || 4000;
app.use('/uploads', express.static(path.join(__dirname, '/uploads')));
app.use(cors());
app.use(logger('dev'));

// Express Body-Parser
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({extended:true}));

// Sync Database
models.sequelize.sync().then(function() {
  console.log('Nice! Database looks fine')
}).catch(function(err) {
  console.log(err, "Something went wrong with the Database Update!")
});

// Passport
app.use(passport.initialize());
app.use(passport.session());

// Routes
app.get('/', (req, res) => {
  res.send('Hello World!')
});
app.use(routes);

// Listening Server
app.listen(PORT, function(){
  console.log(`App listening at http://localhost:${PORT}`)
});