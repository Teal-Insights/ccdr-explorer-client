# FastAPI, Jinja2, PostgreSQL Webapp

![Screenshot](static/screenshot.png)

This project is still under development.

## Installation

`sudo apt update && sudo apt install -y python3-dev libpq-dev && pipx install poetry && poetry install && poetry shell`

## Set environment variables

Copy .env.example to .env with `cp .env.example .env`.

Generate a 256 bit secret key with `openssl rand -base64 32` and paste it into the .env file.

Set your desired database name, username, and password in the .env file.

To use password recovery, register a [Resend](https://resend.com/) account, verify a domain, get an API key, and paste the API key into the .env file.

## Start development database

`docker compose up -d`

## Create database tables and default permissions/roles

`poetry run python migrations/set_up_db.py --drop`

## Run the development server

Make sure the development database is running and tables and default permissions/roles are created first.

`uvicorn main:app --host 0.0.0.0 --port 8000 --reload`

Navigate to http://localhost:8000/

## To do

- Finish implementing role/org system
- Implement user profile page
- Add payments/billing system

## License

This project is licensed under the GPLv3 License. See the LICENSE file for more details.
