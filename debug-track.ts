import request from 'supertest'

async function main () {
  const { createApp } = await import('./server')
  const { app } = await createApp({ inMemoryDb: true })
  const res = await request(app).get('/rest/track-order/%27%20%7C%7C%20true%20%7C%7C%20%27')
  console.log('status', res.status)
  console.log(JSON.stringify(res.body, null, 2))
}

main().catch(err => { console.error(err); process.exit(1) })
