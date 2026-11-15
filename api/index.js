'use strict';
/** Vercel: serve the demo page at the project root. */
const { DEMO_PAGE } = require('../server');

module.exports = (req, res) => {
  if (req.method !== 'GET') {
    res.status(405).json({ error: 'GET only' });
    return;
  }
  res.status(200).setHeader('content-type', 'text/html').send(DEMO_PAGE);
};
