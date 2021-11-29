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
 * -------------- MIDDLEWARE --------------------
 */

app.use((req, res, next) => {
	if (process.env.NODE_ENV === 'development') {
		let now = new Date().toISOString()
		let user_email = (req.session && req.session.user) ? req.session.user.email : null
		console.log(`[${now}] ${req.method} ${req.url} by ${user_email}`)
	}
	next()
})


/**
 * -------------- ROUTES ------------------------
 */
app.get('/', (req, res) => {
	res.render('pages/index')
})

app.get('/login', (req, res) => {
	res.render('pages/login', {message: false})
})

app.get('/logout', checkAuthentication, (req, res) => {
	if (!req.session) res.redirect('/')
	req.session.destroy(err => {
		res.redirect('/')
	})
})

app.get('/add_user', checkAuthenticationAsAdmin, (req, res) => {
	res.render('pages/add_user', {message: false})
})

app.get('/graph', checkAuthentication, (req, res) => {
	res.render('pages/graph')
})

app.get('/access_keys', checkAuthenticationAsAdmin, (req, res) => {
	getAccessKeys((err, accessKeys) => {
		res.render('pages/access_keys', {accessKeys: accessKeys})
	})
})

app.post('/login', (req, res) => {
	const { email, password } = req.body
	validateUser(email, password, (err, user) => {
		if (user) {
			req.session.user = user
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
	getLatest(count, (err, data) => {
		if (err) {
			console.error(err)
			return res.status(500).send('Unable to retrieve data from database.')
		}
		res.type('json').end(JSON.stringify(data, null, 4))
	})
})

app.get('/data(/:count)?', checkAuthentication, (req, res) => {
	let count = req.params.count || 10
	getDataForUser(count, req.session.user.user_id, (err, data) => {
		if (err) {
			console.error(err)
			return res.status(500).send('Unable to retrieve data from database.')
		}
		let thermdata = {}
		data.forEach((row) => {
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

app.use((req, res, next) => {
	res.status(404).render('pages/404')
})


/**
 * -------------- DATABASE ----------------------
 */

const getLatest = (count, callback) => {
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
		if (err) {
			return callback(err)
		}
		return callback(null, result.rows)
	})
}

const getData = (count, callback) => {
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
			return callback(err)
		}
		return callback(null, result.rows)
	})
 }

const getDataForUser = (count, user_id, callback) => {
	const query = {
		text: `
			SELECT
				place, capture_time, temperature
			FROM
				temperature_view
			WHERE
				thermometer_id in (
					SELECT
						thermometer_id
					FROM
						sensors s
						JOIN sensors_users su ON s.sensor_id = su.sensor_id
					WHERE
						su.user_id = $2::integer
				)
			ORDER BY
				capture_time DESC
			LIMIT $1::integer;`,
		values: [count, user_id]
	}
	pool.query(query, (err, result) => {
		if (err) {
			return callback(err)
		}
		return callback(null, result.rows)
	})
}

const getAccessKeys = (callback) => {
	const query = {
		text: `
			SELECT
				u.user_id
				, u.email
				, u.role_id
				, r.role
				, ak.key_id
				, ak.key
				, ak.creation_time
			FROM
				access_keys ak
				LEFT JOIN users u ON u.user_id = ak.owner_id
				LEFT JOIN roles r ON r.role_id = u.role_id;`,
		values: []
	}
	pool.query(query, (err, result) => {
		if (err) {
			return callback(err)
		}
		return callback(null, result.rows)
	})
}

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
	if (!req.session || !req.session.user) {
		res.render('pages/login', {
			message: `To ${req.method} ${req.path} you need to login.`
		})
	} else {
		next()
	}
}

function checkAuthenticationAsAdmin(req, res, next) {
	if (!req.session || !req.session.user) {
		res.render('pages/login', {
			message: `To ${req.method} ${req.path} you need to login.`
		})
	} else if (req.session.user.role !== 'admin') {
		res.render('pages/login', {
			message: `To ${req.method} ${req.path} is only allowed for administrators.`
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
	if (typeof role === 'string') return (role === 'admin') ? 1 : 2;
	if (typeof role === 'number') return (role === 1) ? 'admin' : 'user';
	throw new TypeError
}


/**
 * -------------- SERVER ------------------------
 */

app.listen(PORT, () => {
	console.log(`HTTP server listening at http://localhost:${PORT}`)
})
