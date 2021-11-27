const crypto = require('crypto')
const express = require('express')
const bodyParser = require('body-parser')
const app = express()
const { Pool, Query } = require('pg')
const argon2 = require('argon2')
const session = require('express-session')
const sessionStore = require('connect-pg-simple')


/**
 * -------------- GENERAL SETUP -----------------
 */

require('dotenv').config()
const SESSION_SECRET = 'my very secret string'
const PORT = process.env.PORT
const pool = new Pool()

app.set('view engine', 'ejs')
app.use(bodyParser.urlencoded({ extended: true }))


/**
 * -------------- SESSION SETUP -----------------
 */
app.use(session({
	secret: SESSION_SECRET,
	resave: false, // if unmodified sessions should be rewritten
	saveUninitialized: true,
	store: new (sessionStore(session))({
		pool: pool
	}),
	cookie: {
		secure: 'auto',
		maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
	}
}))


/**
 * -------------- ROUTES ------------------------
 */
app.get('/', (req, res) => {
	res.render('pages/index')
})

app.get('/login', (req, res) => {
	res.render('pages/login', {message: false})
})

app.get('/add_user', checkAuthentication, (req, res) => {
	res.render('pages/add_user', {message: false})
})

app.get('/graph', checkAuthentication, (req, res) => {
	res.render('pages/graph')
})

app.post('/login', (req, res) => {
	const { email, password } = req.body
	validateUser(email, password, (err, user) => {
		if (user) {
			req.session.authenticated = true
			console.log(`User ${user.email} logged in`)
			res.redirect('/graph?count=1000')
		} else {
			res.render('pages/login', {message: 'Invalid username or password'})
		}		
	})
})

app.post('/add_user', checkAuthentication, (req, res) => {
	const { email, phone, role, password, confirmPassword } = req.body;
	if (password !== confirmPassword) {
		res.render('pages/graph', {message: 'Password does not match.'})
		return
	}
	getHashedPassword(password)
		.then(hashedPassword => {
			addUser(email, phone, role, hashedPassword, (err, user_id) => {
				if (err) {
					console.error(err)
				} else {
					console.log(`New user has id ${user_id}.`)
					res.render('pages/login', {
						message: 'Registration Complete. Please login to continue.'
					})
				}
			})
		})
})

app.get('/latest(/:count)?', checkAuthentication, (req, res) => {
	let count = req.params.count || 1
	const query = {
		text: `
			SELECT
				*
			FROM
				temperature_view
			ORDER BY
				capture_time DESC
			LIMIT $1::integer;`,
		values: [count]
	}
	pool.query(query, (err, result) => {
		res.writeHead(200, {
			'content-type': 'text/plain; charset=utf8'
		})
		res.end(JSON.stringify(result.rows, null, 4))
	})
})

app.get('/data(/:count)?', checkAuthentication, (req, res) => {
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


/**
 * -------------- DATABASE ----------------------
 */

const addUser = (email, phone, role, hashedPassword, callback) => {
	let role_id = roleConvert(role)
	const query = {
		text: `	insert into users
				(email, phone, role_id, password)
				values
				($1::text, $2::text, $3::integer, $4::text)
				RETURNING user_id`,
		values: [email, phone, role_id, hashedPassword]
	}
	pool.query(query, (err, result) => {
		if (err) {
			console.log(err)
			return callback(err)
		}
		return callback(null, result.rows[0].user_id)
	})
}

const validateUser = (email, password, callback) => {
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


/**
 * -------------- HELPER FUNCTIONS --------------
 */

function checkAuthentication(req, res, next) {
	if (!req.session || !req.session.authenticated) {
		res.render('pages/login', {
			message: `To ${req.method} ${req.path} you need to login.`
		})
	} else {
		next()
	}
}

async function getHashedPassword(password) {
	let hash
	try {
		hash = await argon2.hash(password)
	} catch (err) {
		console.error(err)
		return err
	}
	return hash
}

function roleConvert(role) {
	return (role === 'admin') ? 1 : 2
}


/**
 * -------------- SERVER ------------------------
 */

app.listen(PORT, () => {
	console.log(`HTTP server listening at http://localhost:${PORT}`)
})
