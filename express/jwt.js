const jwt = require('jsonwebtoken');
const secret = 'MDkxNmZmYjh'

module.exports = function verifyJWT (req, res, next) {
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
        let verifyRet = jwt.verify(token, secret, {ignoreExpiration: true})
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
    resp_msg.status = "ERROR"
    resp_msg.message = "Authorization not found in request header"
  }
  res.json(resp_msg)
}
