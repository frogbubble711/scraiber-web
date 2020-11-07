const chai = require('chai');
const chaiHttp = require('chai-http');
const sinon = require('sinon');
const sinonStubPromise = require('sinon-stub-promise');
const nock = require('nock');
const AWSMock = require('aws-sdk-mock');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const AWS = require('aws-sdk');
const { OAuth2Client } = require('google-auth-library');
const Browser = require('zombie');
const server = require('../app');
const User = require('../models/User');
const Token = require('../models/Token');
const { response } = require('express');

const { expect } = chai;
chai.use(chaiHttp);
// sinonStubPromise(sinon);
Browser.localhost('facebook.com', 5000);

describe('User testing', () => {
  afterEach(async () => {
    await User.deleteMany();
    await Token.deleteMany();
  });
  describe('Register test', () => {
    const sendEmailSpy = sinon.spy();

    beforeEach = (done) => {
      AWSMock.setSDKInstance(AWS);
      done();
    };

    afterEach = (done) => {
      AWSMock.restore('SES');
      done();
    };
    it('Should not register user if email is not provided', (done) => {
      chai
        .request(server)
        .post('/api/users/register')
        .set('Accept', 'application/json')
        .send({})
        .end((err, res) => {
          if (err) {
            return done(err);
          }
          expect(res.status).to.eql(400);
          return done();
        });
    });
    it('Should not register a user if email already exist', (done) => {
      let user = new User({
        firstName: 'Test',
        lastName: 'Test',
        email: 'test@gmail.com',
        password:
          '$2a$10$FUE/6qeL7wf8Dvb9zcgTi.cPuUChhwzTWhe5oBcHdO8rK6zFAPcVi',
        avatar:
          'http://www.gravatar.com/avatar/1aedb8d9dc4751e229a335e371db8058?s=200&r=pg&d=mm',
      });

      user.save().then((user) => {
        const token = new Token({
          _userId: user._id,
          token: crypto.randomBytes(16).toString('hex'),
        });
        token.save(async (error, tkn) => {
          if (error) {
            return done(error);
          }
          chai
            .request(server)
            .post('/api/users/register')
            .send({
              firstName: 'Test',
              lastName: 'Test',
              email: 'test@gmail.com',
              password: 'Test123',
              password_confirm: 'Test123',
            })
            .end((err, res) => {
              if (err) {
                return done(err);
              }
              expect(res.status).to.eql(400);
              expect(res.body).to.be.an('object');
              expect(res.body).to.have.a.property('email');
              expect(res.body.email).to.eql('Email already exists');
              return done();
            });
        });
      });
    });
    it('Should register a user', (done) => {
      chai
        .request(server)
        .post('/api/users/register')
        .send({
          firstName: 'Test',
          lastName: 'Test',
          email: 'test@gmail.com',
          password: 'Test123',
          password_confirm: 'Test123',
        })
        .end((err, res) => {
          if (err) {
            return done(err);
          }
          AWSMock.mock('SES', 'sendEmail', sendEmailSpy);
          expect(sendEmailSpy.calledOnce);
          return done();
        });
    });
  });

  describe('Confirm test', () => {
    it('Should not verify a user if token is invalid', (done) => {
      chai
        .request(server)
        .post('/api/users/confirmation')
        .send({
          token: 'bef1456c3ebabdd0ca155d399419e3c4',
        })
        .end((err, res) => {
          if (err) {
            return done(err);
          }
          expect(res.status).to.eql(400);
          expect(res.body).to.be.an('object');
          expect(res.body).to.have.a.property('msg');
          expect(res.body.msg).to.eql(
            'We were unable to find a valid token. Your token may have expired.',
          );
          return done();
        });
    });
    it('Should not verify a user if found token not match the user', (done) => {
      let user = new User({
        firstName: 'Test',
        lastName: 'Test',
        email: 'test@gmail.com',
        password:
          '$2a$10$FUE/6qeL7wf8Dvb9zcgTi.cPuUChhwzTWhe5oBcHdO8rK6zFAPcVi',
        avatar:
          'http://www.gravatar.com/avatar/1aedb8d9dc4751e229a335e371db8058?s=200&r=pg&d=mm',
        isVerified: true,
      });

      user.save().then(() => {
        const token = new Token({
          _userId: '5f9ed2f8735a481c64137aff',
          token: crypto.randomBytes(16).toString('hex'),
        });
        token.save(async (error, tkn) => {
          if (error) {
            return done(error);
          }
          chai
            .request(server)
            .post('/api/users/confirmation')
            .send({
              token: tkn.token,
            })
            .end((err, res) => {
              if (err) {
                return done(err);
              }
              expect(res.status).to.eql(400);
              expect(res.body).to.be.an('object');
              expect(res.body).to.have.a.property('msg');
              expect(res.body.msg).to.eql(
                'We were unable to find a user for this token.',
              );
              return done();
            });
        });
      });
    });
    it('Should not verify a user if the user is already verified', (done) => {
      let user = new User({
        firstName: 'Test',
        lastName: 'Test',
        email: 'test@gmail.com',
        password:
          '$2a$10$FUE/6qeL7wf8Dvb9zcgTi.cPuUChhwzTWhe5oBcHdO8rK6zFAPcVi',
        avatar:
          'http://www.gravatar.com/avatar/1aedb8d9dc4751e229a335e371db8058?s=200&r=pg&d=mm',
        isVerified: true,
      });

      user.save().then((user) => {
        const token = new Token({
          _userId: user._id,
          token: crypto.randomBytes(16).toString('hex'),
        });
        token.save(async (error, tkn) => {
          if (error) {
            return done(error);
          }
          chai
            .request(server)
            .post('/api/users/confirmation')
            .send({
              token: tkn.token,
            })
            .end((err, res) => {
              if (err) {
                return done(err);
              }
              expect(res.status).to.eql(200);
              expect(res.body).to.be.an('object');
              expect(res.body).to.have.a.property('msg');
              expect(res.body.msg).to.eql(
                'User is already verified. Please continue',
              );
              return done();
            });
        });
      });
    });
    it('Should verify a user', (done) => {
      let user = new User({
        firstName: 'Test',
        lastName: 'Test',
        email: 'test@gmail.com',
        password:
          '$2a$10$FUE/6qeL7wf8Dvb9zcgTi.cPuUChhwzTWhe5oBcHdO8rK6zFAPcVi',
        avatar:
          'http://www.gravatar.com/avatar/1aedb8d9dc4751e229a335e371db8058?s=200&r=pg&d=mm',
      });

      user.save().then((user) => {
        const token = new Token({
          _userId: user._id,
          token: crypto.randomBytes(16).toString('hex'),
        });
        token.save(async (error, tkn) => {
          if (error) {
            return done(error);
          }
          chai
            .request(server)
            .post('/api/users/confirmation')
            .send({
              token: tkn.token,
            })
            .end((err, res) => {
              if (err) {
                return done(err);
              }
              expect(res.status).to.eql(200);
              expect(res.body).to.be.an('object');
              expect(res.body).to.have.a.property('msg');
              expect(res.body.msg).to.eql(
                'The account has been verified. Please log in.',
              );
              return done();
            });
        });
      });
    });
  });

  describe('Login test', () => {
    it('Should not login user if email is not provided', (done) => {
      chai
        .request(server)
        .post('/api/users/login')
        .set('Accept', 'application/json')
        .send({})
        .end((err, res) => {
          if (err) {
            return done(err);
          }
          expect(res.status).to.eql(400);
          return done();
        });
    });

    it('Should not login user if a user not found', (done) => {
      let user = new User({
        firstName: 'Test',
        lastName: 'Test',
        email: 'test1@gmail.com',
        password:
          '$2a$10$FUE/6qeL7wf8Dvb9zcgTi.cPuUChhwzTWhe5oBcHdO8rK6zFAPcVi',
        avatar:
          'http://www.gravatar.com/avatar/1aedb8d9dc4751e229a335e371db8058?s=200&r=pg&d=mm',
        isVerified: true,
      });

      user.save((error, user) => {
        if (error) {
          return done(err);
        }
        chai
          .request(server)
          .post('/api/users/login')
          .send({
            email: 'test2@gmail.com',
            password: 'Test123',
          })
          .end((err, res) => {
            if (err) {
              return done(err);
            }
            expect(res.status).to.eql(404);
            return done();
          });
      });
    });

    it('Should not login user if password is invalid', (done) => {
      let user = new User({
        firstName: 'Test',
        lastName: 'Test',
        email: 'test2@gmail.com',
        password:
          '$2a$10$FUE/6qeL7wf8Dvb9zcgTi.cPuUChhwzTWhe5oBcHdO8rK6zFAPcVi',
        avatar:
          'http://www.gravatar.com/avatar/1aedb8d9dc4751e229a335e371db8058?s=200&r=pg&d=mm',
        isVerified: true,
      });

      user.save((error, user) => {
        if (error) {
          return done(err);
        }
        chai
          .request(server)
          .post('/api/users/login')
          .send({
            email: 'test2@gmail.com',
            password: 'Test111',
          })
          .end((err, res) => {
            if (err) {
              return done(err);
            }
            expect(res.status).to.eql(404);
            return done();
          });
      });
    });
    it('Should login a user', (done) => {
      let user = new User({
        firstName: 'Test',
        lastName: 'Test',
        email: 'test@gmail.com',
        password:
          '$2a$10$FUE/6qeL7wf8Dvb9zcgTi.cPuUChhwzTWhe5oBcHdO8rK6zFAPcVi',
        avatar:
          'http://www.gravatar.com/avatar/1aedb8d9dc4751e229a335e371db8058?s=200&r=pg&d=mm',
        isVerified: true,
      });

      user.save((error, user) => {
        if (error) {
          return done(err);
        }
        chai
          .request(server)
          .post('/api/users/login')
          .send({
            email: 'test@gmail.com',
            password: 'Test123',
          })
          .end((err, res) => {
            if (err) {
              return done(err);
            }
            expect(res.body).to.be.an('object');
            expect(res.body).to.have.a.property('user');
            expect(res.body.success).to.be.true;
            return done();
          });
      });
    });
  });

  describe('Forgot password test', () => {
    const sendEmailSpy = sinon.spy();
    let user = new User({
      firstName: 'Test',
      lastName: 'Test',
      email: 'test@gmail.com',
      password: '$2a$10$FUE/6qeL7wf8Dvb9zcgTi.cPuUChhwzTWhe5oBcHdO8rK6zFAPcVi',
      avatar:
        'http://www.gravatar.com/avatar/1aedb8d9dc4751e229a335e371db8058?s=200&r=pg&d=mm',
    });

    before = async (done) => {
      await user.save();
      done();
    };

    beforeEach = async (done) => {
      //   await user.save();
      AWSMock.setSDKInstance(AWS);
      done();
    };

    afterEach = (done) => {
      AWSMock.restore('SES');
      done();
    };

    it("Should not reset password if email don't exists", (done) => {
      chai
        .request(server)
        .post('/api/users/forgotpassword')
        .send({
          email: 'test1@gmail.com',
        })
        .end((err, res) => {
          if (err) {
            return done(err);
          }
          expect(res.status).to.eql(400);
          expect(res.body).to.be.an('object');
          expect(res.body).to.have.a.property('msg');
          expect(res.body.msg).to.eql("Email don't exist!");
          return done();
        });
    });

    it('Should send reset password link', (done) => {
      chai
        .request(server)
        .post('/api/users/forgotpassword')
        .send({
          email: 'test@gmail.com',
        })
        .end((err, res) => {
          if (err) {
            return done(err);
          }
          AWSMock.mock('SES', 'sendEmail', sendEmailSpy);
          expect(sendEmailSpy.calledOnce);
          return done();
        });
    });
  });

  describe('Reset password test', () => {
    it('Should not reset password if token is invalid', (done) => {
      chai
        .request(server)
        .post('/api/users/reset-password')
        .send({
          token: 'bef1456c3ebabdd0ca155d399419e3c4',
        })
        .end((err, res) => {
          if (err) {
            return done(err);
          }
          expect(res.status).to.eql(400);
          expect(res.body).to.be.an('object');
          expect(res.body).to.have.a.property('msg');
          expect(res.body.msg).to.eql(
            'We were unable to find a valid token. Your token may have expired.',
          );
          return done();
        });
    });

    it('Should reset password', (done) => {
      let user = new User({
        firstName: 'Test',
        lastName: 'Test',
        email: 'test@gmail.com',
        password:
          '$2a$10$FUE/6qeL7wf8Dvb9zcgTi.cPuUChhwzTWhe5oBcHdO8rK6zFAPcVi',
        avatar:
          'http://www.gravatar.com/avatar/1aedb8d9dc4751e229a335e371db8058?s=200&r=pg&d=mm',
      });

      user.save().then((user) => {
        const token = new Token({
          _userId: user._id,
          token: crypto.randomBytes(16).toString('hex'),
        });
        token.save(async (error, tkn) => {
          if (error) {
            return done(error);
          }
          chai
            .request(server)
            .post('/api/users/reset-password')
            .send({
              token: tkn.token,
              newPW: 'Test111',
            })
            .end((err, res) => {
              if (err) {
                return done(err);
              }
              expect(res.status).to.eql(200);
              expect(res.body).to.be.an('object');
              expect(res.body).to.have.a.property('msg');
              expect(res.body.msg).to.eql('Password Update Successfully!');
              return done();
            });
        });
      });
    });
  });

  describe('Google login test', () => {
    let client;
    let verifyIdTokenStub;
    beforeEach(() => {
      client = new OAuth2Client('CLIENT_ID', 'CLIENT_SECRET', 'REDIRECT_URI');
    });

    afterEach(() => { });
    it('Should login a user via google', (done) => {
      const stubValue = {
        payload: {
          email_verified: true,
          given_name: 'Test',
          family_name: 'Test',
          email: 'test@gmail.com',
        },
      };
      const idToken = 'idToken';

      verifyIdTokenStub = sinon
        .stub(client, 'verifyIdToken')
        .resolves(stubValue);
      client.verifyIdToken(idToken, 'aud').then((response) => {
        expect(response.payload).to.be.an('object');
        expect(response.payload.email).to.eql('test@gmail.com');
        done();
      });
      chai
        .request(server)
        .post('/api/users/googlelogin')
        .send({
          tokenId: idToken,
        })
        .end((err, res) => {
          if (err) {
            return done(err);
          }
          expect(verifyIdTokenStub.calledOnce).to.be.true;
          expect(res.body).to.be.an('object');
          expect(res.body).to.have.a.property('user');
          expect(res.body.success).to.be.true;
          return done();
        });
    });
  });

  describe('Facebook login test', () => {
    let userID = '2767432';
    let accessToken = 'test';

    before((done) => {
      const scope = nock('https://graph.facebook.com:443', {
        encodedQueryParams: true,
      })
        .get(
          `/v2.11/${userID}/?fields=id,first_name,last_name,email&access_token=${accessToken}`,
        )
        .reply(200, {
          first_name: 'Test',
          last_name: 'test',
          email: 'test@gmail.com',
        });

      scope.done();
      done();
    });

    afterEach(() => {
      nock.cleanAll();
    });

    it('Should login a user via facebook', (done) => {
      chai
        .request(server)
        .post('/api/users/facebooklogin')
        .send({
          accessToken,
          userID,
        })
        .end((err, res) => {
          if (err) {
            return done(err);
          }
          expect(res.body).to.be.an('object');
          expect(res.body).to.have.a.property('user');
          expect(res.body.success).to.be.true;
          return done();
        });
    });
  });

  describe('User profile test', () => {
    it('Should not return user data if token is invalid', (done) => {
      chai
        .request(server)
        .get('/api/users/me')
        .set(
          'Authorization',
          'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjU5YTA5ZDM0ODYwYTRiMjM0MDEwMTM4MCIsImVtYWlsIjoiYWFAYWEuY29tIiwiaWF0IjoxNTAzODE5MjkwfQ.SnIeTVn-mjA5CukAdzywkTmnHchVa7EdMcvqy9SJjGw',
        )
        .end((err, res) => {
          if (err) {
            return done(err);
          }
          expect(res.status).to.eql(401);
          return done();
        });
    });

    it('Should return user data', (done) => {
      let user = new User({
        firstName: 'Test',
        lastName: 'Test',
        email: 'test@gmail.com',
        password:
          '$2a$10$FUE/6qeL7wf8Dvb9zcgTi.cPuUChhwzTWhe5oBcHdO8rK6zFAPcVi',
        avatar:
          'http://www.gravatar.com/avatar/1aedb8d9dc4751e229a335e371db8058?s=200&r=pg&d=mm',
      });

      user.save().then((user) => {
        const token = new Token({
          _userId: user._id,
          token: crypto.randomBytes(16).toString('hex'),
        });
        token.save(async (error, tkn) => {
          if (error) {
            return done(error);
          }
          let payload = {
            id: user._id,
            firstName: 'Test',
            lastName: 'Test',
            email: 'test@gmail.com',
            password:
              '$2a$10$FUE/6qeL7wf8Dvb9zcgTi.cPuUChhwzTWhe5oBcHdO8rK6zFAPcVi',
            avatar:
              'http://www.gravatar.com/avatar/1aedb8d9dc4751e229a335e371db8058?s=200&r=pg&d=mm',
          };
          jwt.sign(
            payload,
            'secret',
            {
              expiresIn: 3600,
            },
            (err, token) => {
              if (err) return done(err);
              chai
                .request(server)
                .get('/api/users/me')
                .set('Authorization', `Bearer ${token}`)
                .end((err, res) => {
                  if (err) {
                    return done(err);
                  }
                  expect(res.body).to.be.an('object');
                  expect(res.body).to.have.a.property('email');
                  expect(res.body.email).to.eql('test@gmail.com');
                  return done();
                });
            },
          );
        });
      });
    });
  });
});
