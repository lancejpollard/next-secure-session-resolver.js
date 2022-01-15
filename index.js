
const crypto = require('crypto')
const CSRFTokens = require('csrf')
const cookie = require('cookie')
const signature = require('cookie-signature')

const csrfIgnoreMethod = {
  GET: true,
  HEAD: true,
  OPTIONS: true
}

const csrfTokens = new CSRFTokens({
  saltLength: 16,
  secretLength: 32
})

class SecureSessionResolver {
  constructor({
    cookie = 'head',
    secret,
    secure = true,
    find, // find session object from database
    hash = generateRandomHash,
    make,
  }) {
    if (!secret) {
      throw new Error(`Must specify a complex 'secret'.`)
    }

    this.config = {
      cookie,
      secret,
      secure,
      find,
      hash,
      make,
    }
  }

  async resolve(req, res, {
    cookie = this.config.cookie,
    secret = this.config.secret,
    secure = this.config.secure,
    find = this.config.find,
    hash = this.config.hash,
    make = this.config.make,
  }) {
    return await resolve(req, res, {
      cookie,
      secret,
      secure,
      find,
      hash,
      make,
    })
  }
}

module.exports = securify

function securify(opts) {
  return new SecureSessionResolver(opts)
}

async function resolve(req, res, { cookie, secure, secret, find, make } = {}) {
  const csrfSecret = resolveCSRFSecret(req, res, { secure, secret })

  const isVerified = verifyCSRFSecretIfNecessary(req, { secret: csrfSecret })
  if (!isVerified) {
    return { csrf: false, session: false }
  }

  const csrfToken = createCSRFToken({ secret: csrfSecret })
  const oldSession = await resolveSession(req, { cookie, secret, find, make })
  const session = oldSession ?? await createNewSession({ hash, make })

  await cacheSession(res, { cookie, session, secret, secure })

  return {
    session,
    csrf: csrfToken
  }
}

async function remove(req, res) {

}

async function createNewSession({ hash, make }) {
  const token = await hash()
  const expiresAt = addDaysToDate({ count: 30 })
  const session = await make({ token, expiresAt })
  return session
}

async function cacheSession(res, { cookie, session, secret, secure }) {
  setSignedCookie(res, cookie, session.token, secret, {
    path: '/',
    expires: session.expiresAt,
    httpOnly: secure,
    secure: secure,
    sameSite: secure,
  })
}

async function resolveSession(req, { cookie, secret, find, hash, save }) {
  if (!req.headers.cookie) {
    return
  }

  const sessionToken = getCookie(req.cookies, cookie, secret)
  if (!sessionToken) {
    return
  }

  const oldSession = await find({ token: sessionToken })
  if (!oldSession) {
    return
  }

  const newSession = await updateSession({ session: oldSession, hash, save })
  return newSession
}

async function updateSession({ session, hash, save }) {
  const newSession = {}

  if (session.expiresAt <= new Date) {
    newSession.token = await hash()
  } else {
    newSession.token = session.token
  }

  newSession.expiresAt = addDaysToDate({ count: 30 })

  await save({
    oldToken: session.token,
    newToken: newSession.token,
    expiresAt: newSession.expiresAt
  })

  return newSession
}

async function resolveCSRFSecret(req, res, { secret, secure, expirationDurationInDays }) {
  const existingCSRFSecret = getCSRFSecret(req)
  if (existingCSRFSecret) {
    return existingCSRFSecret
  }

  const newCSRFSecret = await csrfTokens.secret()
  const expires = addDaysToDate({ count: 7 })
  setCSRFSecret(res, newCSRFSecret, secret, {
    path: '/',
    expires,
    httpOnly: secure,
    secure: secure,
    sameSite: secure,
  })

  return newCSRFSecret
}

function verifyCSRFSecretIfNecessary(req, { secret }) {
  if (!csrfIgnoreMethod[req.method]) {
    const isVerified = csrfTokens.verify(secret, getCSRFToken(req))
    if (!isVerified) {
      return false // 403 error, Invalid CSRF token.
    }
  }
  return true
}

function createCSRFToken({ secret }) {
  return csrfTokens.create(secret)
}

function generateRandomHex(size = 32) {
  return new Promise((res, rej) => {
    crypto.randomBytes(size, function(err, rnd) {
      if (err) return rej(err)
      res(rnd)
    })
  })
}

async function generateRandomHash() {
  const buffer = await generateRandomHex(32)
  return buffer.toString('hex')
}

function getCookie(cookies, name, secret) {
  let raw
  let val

  raw = cookies[name]

  if (raw) {
    if (raw.substr(0, 2) === 's:') {
      val = signature.unsign(raw.slice(2), secret)

      if (val === false) {
        val = undefined
      }
    } else {
    }
  }

  return val
}

function setSignedCookie(res, name, val, secret, options) {
  const signed = 's:' + signature.sign(val, secret)
  setCookie(res, name, signed, options)
}

function setCookie(res, name, val, options) {
  const data = cookie.serialize(name, val, options)
  const prev = res.getHeader('Set-Cookie') || []
  const header = Array.isArray(prev) ? prev.concat(data) : [prev, data]
  res.setHeader('Set-Cookie', header)
}

function getPotentialIpAddressFromRequest(req) {
  return req.headers['x-real-ip'] || req.connection.remoteAddress
}

function setOauthStateCookie(res, code) {
  setSignedCookie(res, 'code', code, secret, {
    // maxAge:
    // domain:
    path: '/',
    expires: moment().add(7, 'days').toDate(),
    httpOnly: process.env.NODE_ENV === 'production',
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production',
  })
}

function getOauthStateCookie(req) {
  const code = getCookie(req.cookies, 'code', secret)
  if (!code) throw new CloudError('Invalid OAuth state', 403)
  return code
}

function clearOauthStateCookie(req, res) {
  if (req.cookies.code) {
    setCookie(res, 'code', '', {
      path: '/',
      expires: moment().subtract(20, 'years').toDate(),
      httpOnly: process.env.NODE_ENV === 'production',
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production',
    })
  }
}

function addDaysToDate({ date = new Date, count = 1 }) {
  return date.setDate(date.getDate() + count)
}

function setCSRFSecret(res, val, secret, cookie) {
  setSignedCookie(res, 'test', val, secret, cookie)
}

function getCSRFSecret(req) {
  return req.cookies.test
}

function getCSRFToken(req) {
  return (req.headers['csrf-token']) ||
    (req.headers['xsrf-token']) ||
    (req.headers['x-csrf-token']) ||
    (req.headers['x-xsrf-token'])
}
