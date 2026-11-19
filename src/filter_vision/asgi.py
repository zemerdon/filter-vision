"""ASGI entrypoint for the installed Filter Vision WebUI."""
from .app import create_app

app = create_app()
