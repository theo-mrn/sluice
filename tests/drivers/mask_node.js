// node-postgres against sluice, reading rows that must be hidden (run by tests/drivers.py in a container).
const { Client } = require('pg');
(async () => {
  const c = new Client({ host: 'host.docker.internal', port: +process.argv[2], user: 'postgres', database: 'postgres' });
  await c.connect();
  const show = (tag, r) => r.rows.forEach((x) => console.log(tag, x.id, x.email, x.note));
  show('SIMPLE', await c.query('select id, email, note from people where id <= 3 order by id'));
  show('PARAMS', await c.query('select id, email, note from people where id <= $1 order by id', [3]));
  const q = { name: 'p1', text: 'select id, email, note from people where id > $1 order by id', values: [37] };
  show('NAMED1', await c.query(q));
  show('NAMED2', await c.query(q)); // run again: no Describe from the client the second time
  const a = await c.query({ text: 'select id, email from people where id <= 2 order by id', rowMode: 'array' });
  a.rows.forEach((x) => console.log('ARRAY', x[0], x[1]));
  await c.end();
})().catch((e) => { console.log('FATAL ' + e.message); process.exit(1); });
