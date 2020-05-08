const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const User = require('../models/user');
const jwt = require('jsonwebtoken');

const connUri = process.env.MONGO_LOCAL_CONN_URL;

module.exports = {

    login: (req, res) => {
        const { name, password } = req.body;

        mongoose.connect(connUri, { useNewUrlParser: true }, (err) => {
          let result = {};
          let status = 200;
          if(!err) {
            User.findOne({name}, (err, user) => {
              if (!err && user) {
                // We could compare passwords in our model instead of below as well
                bcrypt.compare(password, user.password).then(match => {
                  if (match) {
                    status = 200;
                    // Create a token
                    const payload = { user: user.name };
                    const options = { expiresIn: '2d', issuer: 'https://scotch.io' };
                    const secret = process.env.JWT_SECRET;
                    const token = jwt.sign(payload, secret, options);

                    // console.log('TOKEN', token);
                    result.token = token;
                    result.status = status;
                    result.result = user;
                  }else{
                    status = 401;
                    result.status = status;
                    result.error = `Authentication error`;
                  }
                  res.status(status).send(result);
                }).catch(err => {
                  status = 500;
                  result.status = status;
                  result.error = err;
                  res.status(status).send(result);
                });
              } else {
                status = 404;
                result.status = status;
                result.error = err;
                res.status(status).send(result);
              }
            });
          } else {
            status = 500;
            result.status = status;
            result.error = err;
            res.status(status).send(result);
          }
        })
    },

    getAll: (req, res) => {
        mongoose.connect(connUri, { useNewUrlParser: true }, (err) => {
          let result = {};
          let status = 200;
          if (!err) {
            const payload = req.decoded;
            // TODO: Log the payload here to verify that it's the same payload
            //  we used when we created the token
            // console.log('PAYLOAD', payload);
            if (payload && payload.user === 'admin') {
              User.find({}, (err, users) => {
                if (!err) {
                  result.status = status;
                  result.error = err;
                  result.result = users;
                } else {
                  status = 500;
                  result.status = status;
                  result.error = err;
                }
                res.status(status).send(result);
              });
            } else {
              status = 401;
              result.status = status;
              result.error = `Authentication error`;
              res.status(status).send(result);
            }
          } else {
            status = 500;
            result.status = status;
            result.error = err;
            res.status(status).send(result);
          }
        });
    },

    add: (req, res) => {

      console.log('req:', req.body)
      mongoose.connect(connUri, { useNewUrlParser : true, useUnifiedTopology: true }, (err) => {
        let result = {};
        let status = 201;
        if (!err) {
          console.log('req:', req.body)
          const name = req.body.name;
          const password = req.body.password
          const user = new User({ name, password }); // document = instance of a model
          // TODO: We can hash the password here before we insert instead of in the model
          user.save((err, user) => {
            if (!err) {
              result.status = status;
              result.result = user;
            } else {
              status = 500;
              result.status = status;
              result.error = err;
            }
            res.status(status).send(result);
          });
        } else {
          status = 500;
          result.status = status;
          result.error = err;
          res.status(status).send(result);
        }
      }).catch(err => {
          console.log("Could not connect to mongoose")
          console.log(err);
      })
    },
  }
