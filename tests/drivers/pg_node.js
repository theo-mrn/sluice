// node-postgres against sluice (run by tests/drivers.py in a container). Prints what the application saw.
const { Client } = require('pg');
(async () => {
  const c = new Client({ host: 'host.docker.internal', port: +process.argv[2], user: 'postgres', database: 'postgres' });
  await c.connect();
  const out = [];
  try { await c.query('delete from t where n <= $1', [20]); out.push('NOERROR'); }
  catch (e) { out.push('ERR ' + e.message.split('\n')[0]); }
  try { const r = await c.query(process.argv[3]); out.push('ANSWER ' + r.command + ' ' + r.rowCount); }
  catch (e) { out.push('ERR2 ' + e.message.split('\n')[0]); }
  // a named statement: parsed once, run again
  const q = { name: 'del35', text: 'delete from t where n <= $1', values: [35] };
  try { await c.query(q); out.push('NOERROR2'); } catch (e) { out.push('ERR3 ' + e.message.split('\n')[0]); }
  try { const r = await c.query(process.argv[4]); out.push('ANSWER2 ' + r.command + ' ' + r.rowCount); }
  catch (e) { out.push('ERR4 ' + e.message.split('\n')[0]); }
  console.log(out.join('\n'));
  await c.end();
})().catch((e) => { console.log('FATAL ' + e.message); process.exit(1); });
