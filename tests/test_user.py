import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from main import app
from utils.models import User
