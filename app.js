const crypto = require('crypto')
const express = require('express')
const bodyParser = require('body-parser')
const cookieParser = require('cookie-parser')
const app = express()
const { Pool, Query } = require('pg')
require('dotenv').config()
const argon2 = require('argon2')

app.use(bodyParser.urlencoded({ extended: true }))
app.use(cookieParser())
app.set('view engine', 'ejs')

const PORT = process.env.PORT
const pool = new Pool()

app.use((req, res, next) => {
	const authToken = req.cookies['AuthToken']
	req.user = authTokens[authToken]
	next()
})

app.get('/', (req, res) => {
	res.render('pages/index')
})

app.get('/about', (req, res) => {
	res.render('pages/about')
})

app.get('/login', (req, res) => {
	res.render('pages/login', {message: false})
})

app.get('/registration', (req, res) => {
	res.render('pages/registration', {message: false})
})

app.get('/graph', (req, res) => {
	if (req.user) {
		res.render('pages/graph')
	} else {
		res.render('pages/login', {message: 'The graph data is password protected. Please login.'})
	}
})

app.post('/login', (req, res) => {
	const { email, password } = req.body
	validateUser(email, password, (err, user) => {
		if (user) {
			console.log(`User ${user.email} logged in`)
			const authToken = generateAuthToken()
			authTokens[authToken] = user
			res.cookie('AuthToken', authToken)
			res.redirect('/graph?count=1000')
		} else {
			res.render('pages/login', {message: 'Invalid username or password'})
		}		
	})
})

const authTokens = {} // use other store!

const generateAuthToken = () => {
	return crypto.randomBytes(30).toString('hex')
}

let validateUser = (email, password, callback) => {
	const query = {
		text: `	select
				    u.user_id
				    , u.email
				    , u.phone
				    , r.role
				    , u.password
				from
				    users u
				    left outer join roles r on u.role_id = r.role_id
				where
				    email =  $1::text;`,
		values: [email]
	}
	pool.query(query, (err, result) => {
		if (err) {
			console.error(err)
			return callback(err)
		}

		let user = result.rows[0]

		argon2.verify(user.password, password).then(correct => {
			if (correct) {
				delete user.password
				console.log(user)
				return callback(null, user)
			} else {
				return callback(null, null)
			}
		})
	})
}

app.get('/latest(/:count)?', (req, res) => {
	if (req.user) {
		let count = req.params.count || 1
		pool.query('select * from temperature_view order by capture_time desc limit $1::integer', [count], (err, result) => {
			res.writeHead(200, {
				'content-type': 'text/plain; charset=utf8'
			})
			res.end(JSON.stringify(result.rows, null, 4))
		})
	} else {
		res.redirect('/login')
		
	}
})

app.get('/data(/:count)?', (req, res) => {
	if (!req.user) {
		return res.redirect('/login')
	}
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

app.listen(PORT, () => {
	console.log(`HTTP server listening at http://localhost:${PORT}`)
})
