# README


## FastAPI, Jinja2, PostgreSQL Webapp

![Screenshot of homepage](static/Screenshot.png)

This project is still under development.

### Architecture

This application uses a Post-Redirect-Get (PRG) pattern. The user
submits a form, which sends a POST request to a FastAPI endpoint on the
server. The database is updated, and the user is redirected to a GET
endpoint, which fetches the updated data and re-renders the Jinja2 page
template with the new data.

![Webapp Flow](static/webapp_flow.png)

The advantage of the PRG pattern is that it is very straightforward to
implement and keeps most of the rendering logic on the server side. The
disadvantage is that it requires an extra round trip to the database to
fetch the updated data, and re-rendering the entire page template may be
less efficient than a partial page update on the client side.

### Install development dependencies

#### Python, Docker, and Quarto CLI

- [Python 3.12 or higher](https://www.python.org/downloads/)
- [Docker and Docker Compose](https://docs.docker.com/get-docker/)
- [Quarto CLI](https://quarto.org/docs/get-started/)

#### PostgreSQL headers

For Ubuntu/Debian:

``` bash
sudo apt update && sudo apt install -y python3-dev libpq-dev
```

For macOS:

``` bash
brew install postgresql
```

For Windows:

- No additional system dependencies required
- Install Python from the official Python website

#### Python dependencies

1.  Install Poetry

``` bash
pipx install poetry
```

2.  Install project dependencies

``` bash
poetry install
```

3.  Activate shell

``` bash
poetry shell
```

(Note: You will need to activate the shell every time you open a new
terminal session. Alternatively, you can use the `poetry run` prefix
before other commands to run them without activating the shell.)

### Set environment variables

Copy .env.example to .env with `cp .env.example .env`.

Generate a 256 bit secret key with `openssl rand -base64 32` and paste
it into the .env file.

Set your desired database name, username, and password in the .env file.

To use password recovery, register a [Resend](https://resend.com/)
account, verify a domain, get an API key, and paste the API key into the
.env file.

### Start development database

`docker compose up -d`

### Create database tables and default permissions/roles

`python migrations/set_up_db.py --drop`

### Run the development server

Make sure the development database is running and tables and default
permissions/roles are created first.

`uvicorn main:app --host 0.0.0.0 --port 8000 --reload`

Navigate to http://localhost:8000/

### Render the README

`quarto render README.qmd`

### Contributing

Fork the repository, create a new branch, make your changes, and submit
a pull request.

### License

This project is licensed under the MIT License. See the LICENSE file for
more details.
