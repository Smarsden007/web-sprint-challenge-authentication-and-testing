const secrets = require('../config/secrets.js');
const jwt = require('jsonwebtoken');
const router = require('express').Router();
const Users = require("../users/user-model");
const bcrypt = require('bcryptjs');
const { checkPayload, isUsernameUnique, validateLogin,} = require('../middleware/auth-middleware');

router.post('/register', isUsernameUnique , checkPayload,(req, res, next) => {
  res.end('implement register, please!');

const { username, password } = req.body

  const hash = bcrypt.hashSync(password, 8);
      Users.add({ username, password: hash })
      .then(newUser => {
        res.status(200).json(newUser)
})
      .catch(next)
});





router.post('/login' , validateLogin , checkPayload,(req, res, next) => {
  res.end('implement login, please!');
  const { username, password } = req.body

  Users.findByUsername(username)
  .then(([user]) => {
  if (user && bcrypt.compareSync(password, user.password)) {
    const token = createToken(user)
    res.status(200).json({
      message: `hello ${username}`,
      token
    })
    } else {
      next({ status:401, message: 'invalid credentials' })
    }
  })
  .catch(next)

 });  
 
function createToken(user) {
const payload = {
    subject: user.id,
    username: user.username,

};

const options = {
  expiresIn: '1d',
};
 return jwt.sign(payload, secrets.jwtSecret, options); 
}

module.exports = router;