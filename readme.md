
# Basic Session Implementation for Next.js

A basic piecing together of session management boilerplate from Express.js code and other places, for Next.js.

## Configure the Session Resolver

```js
const SecureSessionResolver = require('@lancejpollard/next-secure-session-resolver.js')

const secureSessionResolver = new SecureSessionResolver({
  cookie: 'food', // fixed cookie name.
  secret: 'a complicated randomly generated password',
  secure: process.env.NODE_ENV === 'production', // in localhost this should be off.
  find,
  hash,
  save,
})

/**
 * Save new token and expiresAt to session.
 */

async function save({ oldToken, newToken, expiresAt }) {
  await knex('session')
    .where('token', oldToken)
    .update({
      token: newToken,
      expires_at: expiresAt
    })
}

/**
 * Hypothetical "find session by token from database".
 */

async function find({ token }) {
  const record = await knex('session')
    .select('*')
    .where('token', token)
    .first()

  return {
    expiresAt: record.expires_at
  }
}

/**
 * Custom hashing function for creating session token.
 */

async function hash() {
  const buffer = await generateRandomHex(32)
  return buffer.toString('hex')
    .replace(/a/g, 'H')
    .replace(/b/g, 'M')
    .replace(/c/g, 'T')
    .replace(/d/g, 'V')
    .replace(/e/g, 'W')
    .replace(/f/g, 'X')
}
```

## Resolve the Session in a Request

```js
export default function handler(req, res) {
  const {
    session,
    csrf
  } = await secureSessionResolver.resolve(req, res)

  if (!csrf) {
    res.status(403).json({ error: 'Invalid CSRF token' })
  } else {
    // continue with handling request.
  }
}
```
