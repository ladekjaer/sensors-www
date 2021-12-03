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
		getUsers((err, users) => {
			res.render('pages/access_keys', {accessKeys: accessKeys, users: users})
		})
	})
})

app.post('/add_access_key', checkAuthenticationAsAdmin, (req, res) => {
	console.log(req.body)
	let { user_email, accessKey } = req.body
	if (!accessKey) accessKey = createAccessKey();

	getUser(user_email, (err, user) => {
		if (err) {
			console.error('Unable to look up user')
			app.locals.message = `Unable to look up user ${user_email}.`
			return res.redirect('/access_keys') // redirect to some 4xx/5xx
		}
		console.log(user)
		addAccessKeys(user, accessKey, (err, add_time) => {
			if (err) {
				console.error('Unable to add access key')
				console.error(err)
				app.locals.message = `Unable to add access key for user ${user.email}.`
				return res.redirect('/access_keys') // redirect to some 4xx/5xx
			}
			console.log(`Access key added for user ${user.email} at ${add_time}`)
			app.locals.message = `Access key added for user ${user.email} at ${add_time.toISOString()}.`
			res.redirect('/access_keys')
		})
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

app.get('/latest_from_each', checkAuthenticationAsAdmin, (req, res) => {
	getLatestFromEachSensor((err, temperatures) => {
		if (err) {
			console.error(err)
			return res.status(500).send('Unable to retrieve wanted data from database.')
		}
		// res.json(temperatures) // This is harder to parse for humans
		res.type('json').end(JSON.stringify(temperatures, null, 4))
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

const getLatestFromEachSensor = (callback) => {
	const query = {
		text: `
			SELECT
				t.temperature_id
				, hostname
				, address
				, place
				, t.thermometer_id
				, pi_id
				, capture_time
				, temperature
			FROM temperature t
				LEFT JOIN sensors s ON s.thermometer_id = t.thermometer_id
				LEFT JOIN addresses a ON a.address_id = s.address_id
			WHERE temperature_id in
					(SELECT MAX(temperature_id)
						FROM temperature
						GROUP BY thermometer_id)
			ORDER BY
				pi_id, place;`,
		values: []
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
				, ak.status
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

const addAccessKeys = (user, accessKey, callback) => {
	if (!user) return callback('No user')
	const query = {
		text: `
			INSERT INTO access_keys
				(owner_id
				, key)
			VALUES
				($1::integer, $2::text)
			RETURNING creation_time;`,
		values: [user.user_id, accessKey]
	}
	pool.query(query, (err, result) => {
		if (err) {
			return callback(err)
		}
		return callback(null, result.rows[0].creation_time)
	})
}

const getUser = (email, callback) => {
	const query = {
		text: `
			SELECT
				user_id
				, email
				, phone
				, role_id
			FROM
				users
			WHERE
				email = $1::text;`,
		values: [email]
	}
	pool.query(query, (err, result) => {
		if (err) {
			console.error(err)
			return callback(err)
		}
		const user = result.rows[0]
		return callback(null, user)
	})
}

const getUsers = callback => {
	const query = {
		text: `
			SELECT
				u.user_id
				, u.email
				, u.phone
				, r.role
			FROM
				users u
				JOIN roles r ON r.role_id = u.role_id;`,
		values: []
	}
	pool.query(query, (err, result) => {
		if (err) {
			console.error(err)
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

function createAccessKey() {
	const key_length = 100
	return crypto.randomBytes(key_length).toString('base64').slice(0, key_length)
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
