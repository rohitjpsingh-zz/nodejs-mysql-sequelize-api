const { Router } =  require('express');
require('../passport');
const loginRouter = require('./login')
const router = Router();

// Define Routes
router.use('/auth', loginRouter);



module.exports = router;