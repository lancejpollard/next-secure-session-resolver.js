const crypto = require('crypto')
const CSRFTokens = require('csrf')
const COOKIE = require('cookie')
const signature = require('cookie-signature')
const dayjs = require('dayjs')

const csrfIgnoreMethod = {
  GET: true,
  HEAD: true,
  OPTIONS: true,
}

function expireSession() {
  return dayjs().add(30, 'day').toDate()
}

function expireOauth() {
  return dayjs().add(7, 'day').toDate()
}

function expireCSRF() {
  return dayjs().add(7, 'day').toDate()
}

module.exports = build

function build({
  session = {
    cookie: {
      name: 'head',
      expire: expireSession,
    },
  },
  oauth = {
    cookie: {
      name: 'code',
      expire: expireOauth,
    },
  },
  csrf = {
    cookie: {
      name: 'test',
      expire: expireCSRF,
    },
    secret: {
      size: 32,
    },
    salt: {
      size: 16,
    },
  },
  secret,
  secure = process.env.NODE_ENV === 'production',
  find,
  hash = generateRandomHash,
  save,
  prefix = 's:',
}) {
  const options = {
    session,
    oauth,
    csrf,
    secret,
    secure,
    find,
    hash,
    save,
    prefix,
  }

  if (!options.secret) {
    throw new Error(`Must specify a complex 'secret'.`)
  }

  const csrfTokenSystem = new CSRFTokens({
    saltLength: options.csrf.salt.size,
    secretLength: options.csrf.secret.size,
  })

  const manager = {
    read,
    write,
    resolve,
    session: {
      fetch: resolveSession,
      cache: cacheSession,
      clear: clearSession,
    },
    oauth: {
      cache: cacheOauthStateCookie,
      fetch: getOauthStateCookie,
      clear: clearOauthStateCookie,
    },
    csrf: {
      clear: clearCSRF,
      token: {
        fetch: getCSRFToken,
        create: createCSRFToken,
      },
      secret: {
        fetch: resolveCSRFSecret,
        verify: verifyCSRFSecret,
        cache: cacheCSRFSecret,
      },
    },
  }

  return manager

  function resolve(req, res) {
    const oldState = read(req)
    const newState = write(res, oldState)
    return newState
  }

  async function read(req) {
    const csrfSecret = await manager.csrf.secret.fetch(req)
    const oldCSRFToken = await manager.csrf.token.fetch(req)
    const verified = await manager.csrf.secret.verify({
      secret: csrfSecret.content,
      token: oldCSRFToken.content,
    })
    const newCSRFToken = verified
      ? await manager.csrf.token.create({
          secret: csrfSecret.content,
        })
      : undefined
    const session = await manager.session.resolve(req)
    const oauthCode = await manager.oauth.fetch(req)

    const state = {
      csrf: {
        secret: oldCSRFSecret,
        token: newCSRFToken,
      },
      oauth: {
        code: oauthCode,
      },
      session,
    }

    return state
  }

  async function write(res, state) {
    const newSession = await updateSession({ session: state.session })

    manager.session.cache(res, { session: newSession })

    if (state.csrf.secret.fresh) {
      manager.csrf.secret.cache(res, {
        secret: state.csrf.secret.content,
      })
    }

    return {
      session: newSession,
      csrf: state.csrf,
    }
  }

  function clearCSRF() {}

  function clearSession() {}

  function verifyCSRFSecret(req, { secret, token }) {
    if (!csrfIgnoreMethod[req.method]) {
      const isVerified = csrfTokenSystem.verify(secret, token)
      if (!isVerified) {
        return false // 403 error, Invalid CSRF token.
      }
    }
    return true
  }

  async function createNewSession() {
    const token = await options.hash()
    const expiration = options.session.cookie.expire()
    return { token, expiration }
  }

  async function cacheSession(res, { session }) {
    setSignedCookie(
      res,
      options.session.cookie.name,
      session.token,
      options.secret,
      {
        path: '/',
        expires: session.expiration,
        httpOnly: secure,
        secure: secure,
        sameSite: secure,
      },
    )
  }

  async function resolveSession(req) {
    const oldSession = await findSession(req)
    if (oldSession) {
      return { record: oldSession, fresh: false }
    }
    const newSession = await createNewSession()
    return { record: newSession, fresh: true }
  }

  async function findSession(req) {
    if (!req.headers.cookie) {
      return
    }

    const sessionToken = getCookie(
      req.cookies,
      options.session.cookie.name,
      options.secret,
      options.prefix,
    )

    if (!sessionToken) {
      return
    }

    return await find({ token: sessionToken })
  }

  async function updateSession({ session }) {
    const newSession = {}

    if (session.expiration <= new Date()) {
      newSession.token = await options.hash()
    } else {
      newSession.token = session.token
    }

    newSession.expiration = options.session.cookie.expire()

    await save({
      oldToken: session.token,
      newToken: newSession.token,
      expiration: newSession.expiration,
    })

    return newSession
  }

  function createCSRFToken({ secret }) {
    return csrfTokenSystem.create(secret)
  }

  function cacheOauthStateCookie(res, { code }) {
    setSignedCookie(
      res,
      options.oauth.cookie.name,
      code,
      options.secret,
      {
        // maxAge:
        // domain:
        path: '/',
        expires: options.oauth.cookie.expire(),
        httpOnly: options.secure,
        secure: options.secure,
        sameSite: options.secure,
      },
    )
  }

  function getOauthStateCookie(req) {
    const code = getCookie(
      req.cookies,
      options.oauth.cookie.name,
      options.secret,
      options.prefix,
    )
    if (!code) throw new CloudError('Invalid OAuth state', 403)
    return code
  }

  function clearOauthStateCookie(res) {
    setCookie(res, options.oauth.cookie.name, '', {
      path: '/',
      expires: dayjs().add(20, 'year').toDate(),
      httpOnly: options.secure,
      secure: options.secure,
      sameSite: options.secure,
    })
  }

  function setCSRFSecret(res, val, secret, data) {
    setSignedCookie(res, options.csrf.cookie.name, val, secret, data)
  }

  function getCSRFSecret(req, { cookie }) {
    return req.cookies[cookie]
  }

  function getCSRFToken(req) {
    return {
      content:
        req.headers['csrf-token'] ||
        req.headers['xsrf-token'] ||
        req.headers['x-csrf-token'] ||
        req.headers['x-xsrf-token'],
    }
  }

  function cacheCSRFSecret(res, { secret, expiration }) {
    setCSRFSecret(res, secret, options.secret, {
      path: '/',
      expires: expiration,
      httpOnly: secure,
      secure: secure,
      sameSite: secure,
    })
  }

  async function resolveCSRFSecret(req) {
    const existingCSRFSecret = getCSRFSecret(req, {
      cookie: options.csrf.cookie.name,
    })

    if (existingCSRFSecret) {
      return { token: existingCSRFSecret, fresh: false }
    } else {
      const newCSRFSecret = await csrfTokenSystem.secret()
      return { token: newCSRFSecret, fresh: true }
    }
  }

  function getCookie(cookies, name, secret, prefix) {
    let raw
    let val

    raw = cookies[name]

    if (raw) {
      if (raw.substr(0, 2) === prefix) {
        val = signature.unsign(raw.slice(2), secret)

        if (val === false) {
          val = undefined
        }
      } else {
      }
    }

    return val
  }

  function setSignedCookie(res, name, val, secret, data) {
    const signed = options.prefix + signature.sign(val, secret)
    setCookie(res, name, signed, data)
  }

  function setCookie(res, name, val, data) {
    const data = COOKIE.serialize(name, val, data)
    const prev = res.getHeader('Set-Cookie') || []
    const header = Array.isArray(prev)
      ? prev.concat(data)
      : [prev, data]
    res.setHeader('Set-Cookie', header)
  }

  function getPotentialIpAddressFromRequest(req) {
    return req.headers['x-real-ip'] || req.connection.remoteAddress
  }
}

function generateRandomHex(size = 32) {
  return new Promise((res, rej) => {
    crypto.randomBytes(size, function (err, rnd) {
      if (err) return rej(err)
      res(rnd)
    })
  })
}

async function generateRandomHash() {
  const buffer = await generateRandomHex(32)
  return buffer.toString('hex')
}
