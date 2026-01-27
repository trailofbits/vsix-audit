// Simple local web server used for testing Extension Attack Suite in ECM3401.
// Ideas taken from tutorial found in: https://www.digitalocean.com/community/tutorials/how-to-create-a-web-server-in-node-js-with-the-http-module

const express = require('express')
const app = express()
const port = 3000

app.get('/', (req, res) => {
  res.send('Malicious Local Web Server!')
})

app.use(express.json());

app.post('/', (req, res) => {
  console.log(req.body)
})

app.listen(port, () => {
  console.log(`App listening at http://localhost:${port}`)
})