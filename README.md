# SAML2 Bearer Token Exchange — WSO2 IS + APIM Demo

A Node.js demo app that logs in via SAML SSO through WSO2 Identity Server, exchanges the SAML assertion for an OAuth2 access token using the SAML2 Bearer Grant, and invokes an API through WSO2 API Manager.

## Setup

```bash
git clone https://github.com/AselaPathirage/saml2-bearer-token-exchange-client.git
cd saml2-bearer-token-exchange-client
npm install
cp .env.example .env   # edit with your values
node app.js
```

Open `http://localhost:3000`.

## Requirements

- WSO2 IS 6.1.0
- WSO2 APIM 4.2.0
- Node.js 16+

## Configuration

See `.env.example` for all configuration options with comments. Two scenarios are supported:

- **Scenario 1** — IS and APIM as separate products. Set `APIM_TOKEN_ENDPOINT` to the APIM token endpoint.
- **Scenario 2** — IS as Resident Key Manager. Set `APIM_TOKEN_ENDPOINT` to the IS token endpoint directly.

## Full Setup Guide

See the Medium article [SAML to OAuth2: Implementing SAML2 Bearer Grant in WSO2 APIM and IS](https://medium.com/@aselapathirage/saml-to-oauth2-implementing-saml2-bearer-grant-in-wso2-apim-and-is-d57024163730) for step-by-step WSO2 IS and APIM configuration for both scenarios.
