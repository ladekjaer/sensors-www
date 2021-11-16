const express = require('express')
const app = express()
const { Pool, Query } = require('pg')
require('dotenv').config()

const PORT = process.env.PORT
const pool = new Pool()

app.get('/latest(/:count)?', (req, res) => {
	let count = req.params.count || 1
	pool.query('select * from temperature_view order by capture_time desc limit $1::integer', [count], (err, result) => {
		res.writeHead(200, {
			'content-type': 'text/plain; charset=utf8'
		})
		res.end(JSON.stringify(result.rows, null, 4))
	})
})

app.get('/data(/:count)?', (req, res) => {
	let count = req.params.count || 10
	const query = {
		text: `
			SELECT
				place, capture_time, temperature
			FROM
				temperature_view
			ORDER BY
				capture_time DESC
			LIMIT $1::integer`,
		values: [count]
	}
	pool.query(query, (err, result) => {
		if (err) {
			console.error(err)
			return res.status(500).send('Unable to retrieve data from database.')
		}
		let thermdata = {}
		result.rows.forEach((row, index) => {
			let measure = {
				x: new Date(row.capture_time),
				y: row.temperature
			}
			if (!thermdata[row.place]) thermdata[row.place] = []
			thermdata[row.place].push(measure)
		})
		res.send(thermdata)
	})
})

app.use(express.static('public'))

app.listen(PORT, () => {
	console.log(`HTTP server listening at http://localhost:${PORT}`)
})
