# Sensors WWW

This webapp is the WWW server to show the data delievered to [Sensors API](https://github.com/ladekjaer/sensors-api) in graphical form in the browser.

## Setup
`sensors-www` need a running PostgreSQL server running.

Clone from GitHub
```sh
$ git clone https://github.com/ladekjaer/sensors-www.git
```
Create and edit the `.env`
```sh
$ cd sensors-www
$ cp .env.example .env
$ vi .env
```
Now simply run it with
```sh
$ node app.js
```
