'use strict';

require('dotenv').config();

const fs           = require('fs');
const https        = require('https');
const express      = require('express');
const session      = require('express-session');
const passport     = require('passport');
const SamlStrategy = require('passport-saml').Strategy;
const axios        = require('axios');

// ─── Validate required env vars ───────────────────────────────────────────────
const REQUIRED = [
  'SP_ENTITY_ID', 'SP_CALLBACK_URL',
  'IDP_SSO_URL',  'IDP_CERT_PATH',
  'APIM_TOKEN_ENDPOINT', 'APIM_CONSUMER_KEY', 'APIM_CONSUMER_SECRET',
  'APIM_API_ENDPOINT',
];
for (const key of REQUIRED) {
  if (!process.env[key]) {
    console.error(`Missing required env var: ${key}`);
    process.exit(1);
  }
}

// ─── HTTPS agent (ignore self-signed certs — dev only) ────────────────────────
const httpsAgent = new https.Agent({ rejectUnauthorized: false });

// ─── Passport SAML strategy ───────────────────────────────────────────────────
// Load optional SP signing key/cert (required when IS enforces AuthnRequest signing)
const spPrivateKey = process.env.SP_PRIVATE_KEY_PATH && fs.existsSync(process.env.SP_PRIVATE_KEY_PATH)
  ? fs.readFileSync(process.env.SP_PRIVATE_KEY_PATH, 'utf8')
  : null;
const spCert = process.env.SP_CERT_PATH && fs.existsSync(process.env.SP_CERT_PATH)
  ? fs.readFileSync(process.env.SP_CERT_PATH, 'utf8')
  : null;

if (!spPrivateKey) {
  console.warn(
    '[WARN] SP_PRIVATE_KEY_PATH not set — AuthnRequests will be unsigned.\n' +
    '       If IS rejects with "Signature validation failed", either:\n' +
    '       (a) generate a key pair and set SP_PRIVATE_KEY_PATH / SP_CERT_PATH, or\n' +
    '       (b) uncheck "Enable Signature Validation" in the IS SP config.'
  );
}

const samlStrategy = new SamlStrategy(
  {
    // SP settings
    callbackUrl:          process.env.SP_CALLBACK_URL,
    issuer:               process.env.SP_ENTITY_ID,
    logoutCallbackUrl:    process.env.SP_LOGOUT_CALLBACK_URL,

    // IdP settings
    entryPoint:           process.env.IDP_SSO_URL,
    logoutUrl:            process.env.IDP_LOGOUT_URL,
    cert:                 fs.readFileSync(process.env.IDP_CERT_PATH, 'utf8'),

    // SP signing key — signs the AuthnRequest sent to IS.
    // Required when IS SP config has "Enable Signature Validation" checked.
    ...(spPrivateKey && {
      privateKey:         spPrivateKey,
      signingCert:        spCert,
    }),

    // Assertion validation
    wantAssertionsSigned: true,
    acceptedClockSkewMs:  5000,     // tolerate minor clock drift between IS and app
  },
  (profile, done) => done(null, profile)
);

passport.use(samlStrategy);
passport.serializeUser((user, done)   => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// ─── Express setup ────────────────────────────────────────────────────────────
const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret:            process.env.SESSION_SECRET || 'dev-secret',
  resave:            false,
  saveUninitialized: false,
  cookie:            { secure: false },   // set true if behind HTTPS
}));
app.use(passport.initialize());
app.use(passport.session());

// ─── Routes ───────────────────────────────────────────────────────────────────

/**
 * Home — shows login state, token, and action buttons.
 */
app.get('/', (req, res) => {
  if (!req.isAuthenticated()) {
    return res.send(html(`
      <h2>SAML SSO → APIM Demo</h2>
      <a class="btn" href="/login">Login with SAML (WSO2 IS)</a>
    `));
  }

  const token      = req.session.accessToken;
  const tokenError = req.session.tokenError;
  const apiResp    = req.session.apiResponse;
  const hasSaml    = !!req.session.rawSamlResponse;

  res.send(html(`
    <h2>Logged in</h2>
    <table>
      <tr><th>Name ID</th><td>${esc(req.user.nameID)}</td></tr>
      <tr><th>Session Index</th><td>${esc(req.user.sessionIndex || '—')}</td></tr>
    </table>

    <h3>OAuth2 Token</h3>
    ${ token
      ? `<p class="ok">✔ Token obtained</p><pre>${esc(token)}</pre>`
      : tokenError
        ? `<p class="err">✘ Token exchange failed</p><pre>${esc(tokenError)}</pre>
           ${ hasSaml ? `<form method="POST" action="/get-token"><button class="btn">Retry Token Exchange</button></form>` : '' }`
        : hasSaml
          ? `<p class="note">SAML assertion ready. Click below to exchange it for an OAuth2 token.</p>
             <form method="POST" action="/get-token"><button class="btn">Get Token</button></form>`
          : '<p class="note">Token not available.</p>'
    }

    <h3>Invoke APIM API</h3>
    ${ token
      ? `<form method="POST" action="/invoke-api"><button class="btn">Invoke API</button></form>`
      : '<p class="note">Token required to invoke API.</p>'
    }
    ${ apiResp ? `<h4>API Response</h4><pre>${esc(apiResp)}</pre>` : '' }

    <br><a href="/logout">Logout</a>
  `));
});

/**
 * Initiates SAML SSO redirect to IS.
 */
app.get('/login',
  passport.authenticate('saml', { failureRedirect: '/' })
);

/**
 * SAML callback — IS POSTs the SAMLResponse here after authentication.
 * Passport validates the assertion, then we store the raw SAMLResponse
 * in the session so the user can exchange it for an OAuth2 token on demand.
 */
app.post('/callback',
  passport.authenticate('saml', {
    failureRedirect: '/',
    failureMessage:  true,
  }),
  (req, res) => {
    // Store the raw SAMLResponse so the user can exchange it on demand.
    req.session.rawSamlResponse = req.body.SAMLResponse;
    console.log('[callback] SAML authentication successful, SAMLResponse stored in session');

    req.session.save((err) => {
      if (err) console.error('[callback] session save error:', err);
      res.redirect('/');
    });
  }
);

/**
 * Extracts the SAML assertion from the stored SAMLResponse and
 * exchanges it for an OAuth2 access token at the APIM token endpoint.
 */
app.post('/get-token', async (req, res) => {
  console.log('[get-token] isAuthenticated:', req.isAuthenticated());
  console.log('[get-token] rawSamlResponse present:', !!req.session.rawSamlResponse);

  if (!req.isAuthenticated() || !req.session.rawSamlResponse) {
    return res.redirect('/');
  }

  try {
    const fullResponse = extractAssertion(req.session.rawSamlResponse);
    console.log('[get-token] assertion (base64url, first 80 chars):', fullResponse.slice(0, 80));

    const body = new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:saml2-bearer',
      assertion: fullResponse,
      scope: 'PRODUCTION',
    });

    const basicCreds = Buffer.from(
      `${process.env.APIM_CONSUMER_KEY}:${process.env.APIM_CONSUMER_SECRET}`
    ).toString('base64');

    const { data } = await axios.post(
      process.env.APIM_TOKEN_ENDPOINT,
      body.toString(),
      {
        headers: {
          'Authorization':  `Basic ${basicCreds}`,
          'Content-Type':   'application/x-www-form-urlencoded',
        },
        httpsAgent,
      }
    );

    req.session.accessToken = data.access_token;
    res.redirect('/');

  } catch (err) {
    const detail = err.response?.data ?? err.message;
    res.status(502).send(html(`
      <h3>Token exchange failed</h3>
      <pre>${esc(JSON.stringify(detail, null, 2))}</pre>
      <h4>Troubleshooting</h4>
      <ul>
        <li>IS SP config Audience include: <code>${esc(process.env.SP_CALLBACK_URL)}</code> and <code>${esc(process.env.APIM_TOKEN_ENDPOINT)}</code></li>
        <li>IS public cert in APIM IdP config must match <code>${esc(process.env.IDP_CERT_PATH)}</code></li>
        <li>Consumer key/secret must be from the APIM Developer Portal app</li>
      </ul>
      <a href="/">Back</a>
    `));
  }
});

/**
 * Invokes the APIM-protected API using the stored OAuth2 access token.
 */
app.post('/invoke-api', async (req, res) => {
  if (!req.session.accessToken) {
    return res.redirect('/');
  }

  try {
    const { data, status } = await axios.get(
      process.env.APIM_API_ENDPOINT,
      {
        headers: { 'Authorization': `Bearer ${req.session.accessToken}` },
        httpsAgent,
      }
    );

    req.session.apiResponse = JSON.stringify({ status, data }, null, 2);
    res.redirect('/');

  } catch (err) {
    const detail = err.response?.data ?? err.message;
    req.session.apiResponse = JSON.stringify(
      { error: detail, status: err.response?.status },
      null, 2
    );
    res.redirect('/');
  }
});

/**
 * Logout — initiates SAML Single Logout (SLO).
 */
app.get('/logout', (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect('/');
  }

  samlStrategy.logout(req, (err, requestUrl) => {
    req.logout(() => {
      req.session.destroy((destroyErr) => {
        if (destroyErr) console.error('[logout] session destroy error:', destroyErr);
        res.clearCookie('connect.sid');

        if (err || !requestUrl) {
          // SLO URL generation failed — fall back to local logout only
          console.warn('[logout] SLO request failed, doing local logout only:', err?.message);
          return res.redirect('/');
        }

        // Redirect to IS to invalidate the IS SSO session
        console.log('[logout] redirecting to IS for SLO:', requestUrl);
        res.redirect(requestUrl);
      });
    });
  });
});

/**
 * IS redirects back here after completing Single Logout.
 * IS uses POST binding for the SLO response.
 */
app.post('/logout/callback', (req, res) => {
  console.log('[logout/callback] SLO complete (POST)');
  res.redirect('/');
});

app.get('/logout/callback', (req, res) => {
  console.log('[logout/callback] SLO complete (GET)');
  res.redirect('/');
});


// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Extracts the <saml:Assertion> element from a base64-encoded SAMLResponse
 * and returns it as a base64-URL-encoded string (no padding) suitable for
 * use as the `assertion` parameter in the SAML2 Bearer Grant request.
 *
 * SAML assertions are nested inside the SAMLResponse wrapper. The token
 * endpoint expects only the Assertion element, not the full Response.
 */
function extractAssertion(samlResponseBase64) {
  const xml = Buffer.from(samlResponseBase64, 'base64').toString('utf8');

  // Extract and print the signing cert in PEM format — copy this exactly into APIM IdP config
  const certMatch = xml.match(/<ds:X509Certificate>([\s\S]*?)<\/ds:X509Certificate>/);
  if (certMatch) {
    const certB64 = certMatch[1].replace(/\s/g, '');
    const pem = '-----BEGIN CERTIFICATE-----\n' +
      certB64.match(/.{1,64}/g).join('\n') +
      '\n-----END CERTIFICATE-----';
    console.log('\n─── IS Signing Certificate (PEM) — upload this to APIM IdP config ───');
    console.log(pem);
    console.log('──────────────────────────────────────────────────────────────────\n');
  }

  // Handles both saml: and saml2: namespace prefixes
  const match = xml.match(/<saml(?:2)?:Assertion[\s\S]*?<\/saml(?:2)?:Assertion>/);
  if (!match) {
    throw new Error(
      'Could not find <saml:Assertion> in SAMLResponse.\n' +
      'Decoded XML:\n' + xml.slice(0, 500)
    );
  }

  console.log('─── Extracted <saml:Assertion> ───────────────────────────────────');
  console.log(match[0]);
  console.log('──────────────────────────────────────────────────────────────────\n');

  // RFC 4648 §5 base64url — replace + with -, / with _, strip padding
  return Buffer.from(match[0])
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/** HTML escaping to prevent XSS in server-rendered output */
function esc(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/** Minimal HTML page wrapper */
function html(body) {
  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>SAML + APIM Demo</title>
  <style>
    body  { font-family: sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; }
    table { border-collapse: collapse; margin: 10px 0; }
    td, th { border: 1px solid #ccc; padding: 6px 12px; text-align: left; }
    pre   { background: #f4f4f4; padding: 12px; overflow-x: auto; font-size: 13px; }
    .btn  { padding: 8px 16px; background: #005a9c; color: #fff; border: none; cursor: pointer; text-decoration: none; display: inline-block; }
    .ok   { color: green; font-weight: bold; }
    .err  { color: red; font-weight: bold; }
    .note { color: #888; }
    code  { background: #eee; padding: 2px 4px; }
  </style>
</head>
<body>${body}</body>
</html>`;
}

// ─── Start ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\nApp running at http://localhost:${PORT}`);
});
