'use strict';
const express = require('express');
const path = require('path');
const serverless = require('serverless-http');
const app = express();
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');

const verifyJWT = (req, res, next) => {
  let headers = req.headers
  let resp_msg = {status: 'SUCCESS'}
  let auth = ''
  let tokenFromHeader = false
  if (headers['authorization']) {
    tokenFromHeader = true
    auth = headers['authorization']
  } else if (req.body && req.body.t) {
    auth = req.body.t
  }
  if (auth) {
    let token = auth.indexOf('Bearer') > -1 ? auth.substring(auth.indexOf('Bearer') + 7):auth
    // let token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImJpbmdfYWRtaW5AeW9wbWFpbC5jb20iLCJleHAiOiIxNTgyMDgzNTM3IiwiaWF0IjoiMTU4MTk5NzEzNyIsImp0aSI6ImQ0N2UwMDZhLTVlN2YtNGY1My1hNDhjLWVkMGE4NWFlYjQ5NCIsIm9yZ19pZCI6IlBXSmlMTUNkWnRTOU9LWEM2ZDg4Sk9FIn0.ur4_Lo6iSrqbA55jEqaUN0ZGYnOlKChpFBLT70KuQ2o'
    if (token) {
      token = token.trim()
    }
    if (!token) {
      resp_msg.status = "ERROR",
        resp_msg.message = "Invalid token found in request header"
    } else {
      resp_msg.jwt = {}
      resp_msg.jwt.payload = jwt.decode(token)
      try {
        let verifyRet = jwt.verify(token, config.client_secret, {ignoreExpiration: true})
        verifyRet && (resp_msg.jwt.verification_result = {status: 'Valid'})
      } catch (e) {
        resp_msg.jwt.verification_result = {status: 'Invalid', error_msg: e}
      }
      if (tokenFromHeader) {
        resp_msg.jwt.from = "HEADER"
      } else {
        resp_msg.jwt.from = "POST-BODY"
      }
    }

  } else {
    resp_msg.status = "ERROR",
      resp_msg.message = "Authorization not found in request header"
  }
  res.json(resp_msg)
}

const router = express.Router();
router.get('/', (req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.write('<h1>Hello from Express.js!</h1>');
  res.end();
});
router.get('/another', (req, res) => res.json({ route: req.originalUrl }));
router.post('/', verifyJWT);

app.use(bodyParser.json());
app.use('.netlify/functions/server', router);  // path must route to lambda

module.exports = app;
module.exports.handler = serverless(app);
