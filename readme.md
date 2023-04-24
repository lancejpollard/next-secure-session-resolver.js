# Basic Session Implementation for Next.js

A basic piecing together of session management boilerplate from Express.js code and other places, for Next.js.

## Configure the Session Resolver

```js
import resolver from '@lancejpollard/next-secure-session-resolver.js'

const manager = resolver({
  secret: 'a complicated randomly generated password',
  secure: process.env.NODE_ENV === 'production', // in localhost this should be off.
  find,
  hash,
  save,
});

export default manager

/**
 * Save new token and expiresAt to session.
 */

async function save({ oldToken, newToken, expiration }) {
  await knex('session').where('token', oldToken).update({
    token: newToken,
    expires_at: expiration,
  });
}

/**
 * Hypothetical 'find session by token from database'.
 */

async function find({ token }) {
  const record = await knex('session')
    .select('*')
    .where('token', token)
    .first();

  return {
    expiration: record.expires_at,
  };
}

/**
 * Custom hashing function for creating session token.
 */

async function hash() {
  const buffer = await generateRandomHex(32);
  return buffer
    .toString('hex')
    .replace(/a/g, 'H')
    .replace(/b/g, 'M')
    .replace(/c/g, 'T')
    .replace(/d/g, 'V')
    .replace(/e/g, 'W')
    .replace(/f/g, 'X');
}
```

## Resolve the Session in a Request

```js
import manager from './session'

export default function handler(req, res) {
  const state = await manager.resolve(req, res)

  if (!state.csrf.token) {
    return res.status(403).json({ error: 'Invalid CSRF token' })
  }

  // continue
}
```
