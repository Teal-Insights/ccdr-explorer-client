# FastAPI, Jinja2, PostgreSQL Webapp

This project is still under development.

## Installation

`sudo apt update && sudo apt install -y python3-dev libpq-dev && pipx install poetry && poetry install && poetry shell`

## Start development database

`docker compose up -d`

## Set environment variables

Copy .env.example to .env with `cp .env.example .env`.

Generate a 256 bit secret key with `openssl rand -base64 32` and paste it into the .env file.

Set your desired database name, username, and password in the .env file.

## Run the development server

`uvicorn main:app --host 0.0.0.0 --port 8000 --reload`

Navigate to http://localhost:8000/

## License

This project is licensed under the GPLv3 License. See the LICENSE file for more details.
