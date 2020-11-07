const express = require('express');
const router = express.Router();
const gravatar = require('gravatar');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const crypto = require('crypto');

var AWS = require("aws-sdk");
// Set the region
AWS.config.update({ region: "us-east-2" });

const validateRegisterInput = require('../validation/register');
const validateLoginInput = require('../validation/login');
const { OAuth2Client } = require('google-auth-library');
const fetch = require('node-fetch');

const clientId = "";
const client = new OAuth2Client(clientId);

const User = require('../models/User');
const Token = require('../models/Token');

function isAuthenticated(req, res, next) {
  // do any checks you want to in here
  const bearerHeader = req.headers['authorization'];
  // Check if bearer is undefined
  if (typeof bearerHeader !== 'undefined') {
    // Split at the space
    const bearer = bearerHeader.split(' ');
    // Get token from array
    const bearerToken = bearer[1];
    // Set the token
    req.token = bearerToken;
    // Next middleware
    next();
  } else {
    // Forbidden
    res.sendStatus(403);
  }
}

router.post('/register', function (req, res) {
  const originUrl = req.get('origin');
  const { errors, isValid } = validateRegisterInput(req.body);

  if (!isValid) {
    return res.status(400).json(errors);
  }
  User.findOne({
    email: req.body.email
  }).then(user => {
    if (user) {
      return res.status(400).json({
        email: 'Email already exists'
      });
    }
    else {
      const avatar = gravatar.url(req.body.email, {
        s: '200',
        r: 'pg',
        d: 'mm'
      });
      const newUser = new User({
        firstName: req.body.firstName,
        lastName: req.body.lastName,
        email: req.body.email,
        password: req.body.password,
        avatar
      });

      bcrypt.genSalt(10, (err, salt) => {
        if (err) console.error('There was an error', err);
        else {
          bcrypt.hash(newUser.password, salt, (err, hash) => {
            if (err) console.error('There was an error', err);
            else {
              newUser.password = hash;
              newUser
                .save()
                .then(user => {
                  const token = new Token({
                    _userId: user._id,
                    token: crypto.randomBytes(16).toString('hex'),
                  });
                  token.save(async (err) => {
                    if (err) {
                      return res.send({
                        statue: 'error',
                        msg: 'Something went wrong during sending verify message!',
                        data: err.message,
                      });
                    }
                    var params = {
                      Destination: {
                        /* required */

                        ToAddresses: [
                          user.email /* to change; generate new one https://temp-mail.org/en */,
                        ],
                      },
                      Message: {
                        /* required */
                        Body: {
                          /* required */
                          Html: {
                            Charset: "UTF-8",
                            Data: `${originUrl}/confirmation/${token.token}`,
                          }
                        },
                        Subject: {
                          Charset: "UTF-8",
                          Data: "Check mail",
                        },
                      },
                      Source: ''/* required */,
                    };
                    // Create the promise and SES service object
                    var sendPromise = new AWS.SES({ apiVersion: "2010-12-01" })
                      .sendEmail(params)
                      .promise();

                    // Handle promise's fulfilled/rejected states
                    sendPromise
                      .then(function (data) {
                        res.send({
                          statue: 'success',
                          msg: `A verification email has been sent to ${user.email}.`,
                        });
                      })
                      .catch(function (err) {
                        res.status(400);
                        return res.send({
                          statue: 'error',
                          msg: 'Something went wrong during sending verify message!123',
                          data: err.message,
                        });
                      });
                  })
                });
            }
          });
        }
      });
    }
  });
});

router.post('/login', (req, res) => {

  const { errors, isValid } = validateLoginInput(req.body);

  if (!isValid) {
    return res.status(400).json(errors);
  }

  const email = req.body.email;
  const password = req.body.password;

  User.findOne({ email })
    .then(user => {
      if (!user) {
        return res.status(404).json(errors);
      }
      bcrypt.compare(password, user.password)
        .then(isMatch => {
          if (isMatch) {
            if (!user.isVerified) {
              errors.password = 'This user is not verified';
              return res.status(400).json(errors);
            }
            const payload = {
              id: user.id,
              firstName: user.firstName,
              lastName: user.lastName,
              email: user.email,
              avatar: user.avatar
            }
            jwt.sign(payload, 'secret', {
              expiresIn: 3600
            }, (err, token) => {
              if (err) console.error('There is some error in token', err);
              else {
                res.json({
                  success: true,
                  token: token,
                  user: payload
                });
              }
            });
          }
          else {
            return res.status(404).json(errors);
          }
        });
    });
});

router.post('/forgotpassword', (req, res) => {
  const originUrl = req.get('origin');
  User.findOne({ email: req.body.email }).then((user) => {
    if (!user) {
      return res.status(400).send({ msg: "Email don't exist!" });
    }
    const token = new Token({
      _userId: user._id,
      token: crypto.randomBytes(16).toString('hex'),
    });

    token.save(async function (err) {
      if (err) {
        return res.status(500).send({ msg: err.message });
      }
      var params = {
        Destination: {
          /* required */

          ToAddresses: [
            user.email /* to change; generate new one https://temp-mail.org/en */,
          ],
        },
        Message: {
          /* required */
          Body: {
            /* required */
            Html: {
              Charset: "UTF-8",
              Data: `${originUrl}/reset-password/${token.token}`,
            }
          },
          Subject: {
            Charset: "UTF-8",
            Data: "Click the link to change your password!",
          },
        },
        Source: ''/* required */,
      };
      // Create the promise and SES service object
      var sendPromise = new AWS.SES({ apiVersion: "2010-12-01" })
        .sendEmail(params)
        .promise();

      // Handle promise's fulfilled/rejected states
      sendPromise
        .then(function (data) {
          res.send({
            statue: 'success',
            msg: `A verification email has been sent to ${user.email}.`,
          });
        })
        .catch(function (err) {
          return res.status(500).send({ msg: err.message });
        });
    });
  });
})

router.post('/reset-password', (req, res) => {
  Token.findOne({ token: req.body.token }, function (err, token) {
    if (!token)
      return res.status(400).send({
        msg:
          'We were unable to find a valid token. Your token may have expired.',
      });
    bcrypt.genSalt(10, (err, salt) => {
      if (err) {
        throw err;
      } else {
        bcrypt.hash(req.body.newPW, salt, (err, hash) => {
          if (err) throw err;
          req.body.newPW = hash;
          User.findOneAndUpdate(
            { _id: token._userId },
            { password: req.body.newPW },
            (err) => {
              if (err) {
                return res.status(404).send({ msg: err });
              }
            }
          )
            .then((user) => {
              res.status(200).send({ msg: 'Password Update Successfully!' });
            })
            .catch((err) => {
              res.send({ msg: err });
            });
        });
      }
    });
  });
})

router.post('/confirmation', (req, res) => {
  Token.findOne({ token: req.body.token }, function (err, token) {
    if (!token) {
      return res.status(400).send({
        type: 'not-verified',
        msg:
          'We were unable to find a valid token. Your token may have expired.',
      });
    }

    // If we found a token, find a matching user
    User.findOne({ _id: token._userId }, function (err, user) {
      if (!user) {
        return res
          .status(400)
          .send({ msg: 'We were unable to find a user for this token.' });
      }

      if (user.isVerified) {
        return res.status(200).send({
          type: 'already-verified',
          msg: 'User is already verified. Please continue',
        });
      }

      // Verify and save the user
      user.isVerified = true;
      user.save(function (err) {
        if (err) {
          return res.status(500).send({ msg: err.message });
        }
        res
          .status(200)
          .send({ msg: 'The account has been verified. Please log in.' });
      });
    });
  });
})

router.post('/googlelogin', (req, res) => {
  const { tokenId } = req.body;
  client.verifyIdToken({ idToken: tokenId, audience: clientId }).then(response => {
    const { email_verified, given_name, family_name, email } = response.payload;
    const firstName = given_name;
    const lastName = family_name;

    if (email_verified) {
      User.findOne({ email }).exec((err, user) => {
        if (err) {
          return res.status(400).json({
            error: "Something went wrong..."
          })
        } else {
          if (user) {
            const payload = {
              id: user.id,
              firstName: user.firstName,
              lastName: user.lastName,
              email: user.email,
              avatar: user.avatar
            }
            jwt.sign(payload, 'secret', {
              expiresIn: 3600
            }, (err, token) => {
              if (err) console.error('There is some error in token', err);
              else {
                res.json({
                  success: true,
                  token: token,
                  user: payload
                });
              }
            });
          } else {
            const avatar = gravatar.url(email, {
              s: '200',
              r: 'pg',
              d: 'mm'
            });
            const password = email + process.env.JWT_SIGNIN_KEY;
            const newUser = new User({
              firstName: firstName,
              lastName: lastName,
              email: email,
              password: password,
              avatar
            });

            bcrypt.genSalt(10, (err, salt) => {
              if (err) console.error('There was an error', err);
              else {
                bcrypt.hash(newUser.password, salt, (err, hash) => {
                  if (err) console.error('There was an error', err);
                  else {
                    newUser.password = hash;
                    newUser
                      .save()
                      .then(user => {
                        const payload = {
                          id: user.id,
                          firstName: user.firstName,
                          lastName: user.lastName,
                          email: user.email,
                          avatar: user.avatar
                        }
                        jwt.sign(payload, 'secret', {
                          expiresIn: 3600
                        }, (err, token) => {
                          if (err) console.error('There is some error in token', err);
                          else {
                            res.json({
                              success: true,
                              token: token,
                              user: payload
                            });
                          }
                        });
                      });
                  }
                });
              }
            });
          }
        }
      })
    }
  })
})

router.post('/facebooklogin', (req, res) => {
  const { accessToken, userID } = req.body;

  let urlGraphFacebook = `https://graph.facebook.com/v2.11/${userID}/?fields=id,first_name,last_name,email&access_token=${accessToken}`;
  fetch(urlGraphFacebook, {
    method: "GET"
  })
    .then(response => response.json())
    .then(response => {
      const { first_name, last_name, email } = response;
      const firstName = first_name;
      const lastName = last_name;
      User.findOne({ email }).exec((err, user) => {
        if (err) {
          return res.status(400).json({
            error: "Something went wrong..."
          })
        } else {
          if (user) {
            const payload = {
              id: user.id,
              firstName: user.firstName,
              lastName: user.lastName,
              email: user.email,
              avatar: user.avatar
            }
            jwt.sign(payload, 'secret', {
              expiresIn: 3600
            }, (err, token) => {
              if (err) console.error('There is some error in token', err);
              else {
                res.json({
                  success: true,
                  token: token,
                  user: payload
                });
              }
            });
          } else {
            const avatar = gravatar.url(email, {
              s: '200',
              r: 'pg',
              d: 'mm'
            });
            const password = email + process.env.JWT_SIGNIN_KEY;
            const newUser = new User({
              firstName: firstName,
              lastName: lastName,
              email: email,
              password: password,
              avatar
            });

            bcrypt.genSalt(10, (err, salt) => {
              if (err) console.error('There was an error', err);
              else {
                bcrypt.hash(newUser.password, salt, (err, hash) => {
                  if (err) console.error('There was an error', err);
                  else {
                    newUser.password = hash;
                    newUser
                      .save()
                      .then(user => {
                        const payload = {
                          id: user.id,
                          firstName: user.firstName,
                          lastName: user.lastName,
                          email: user.email,
                          avatar: user.avatar
                        }
                        jwt.sign(payload, 'secret', {
                          expiresIn: 3600
                        }, (err, token) => {
                          if (err) console.error('There is some error in token', err);
                          else {
                            res.json({
                              success: true,
                              token: token,
                              user: payload
                            });
                          }
                        });
                      });
                  }
                });
              }
            });
          }
        }
      })
    })
})

router.get('/me', passport.authenticate('jwt', { session: false }), (req, res) => {
  return res.json({
    id: req.user.id,
    name: req.user.name,
    email: req.user.email
  });
});

module.exports = router;
