#!/usr/bin/env python3

from flask import Flask
from flask_socketio import SocketIO, send

# Initialize Flask app
app = Flask(__name__)
app.config["DEBUG"] = True

# Initialize SocketIO
socketio = SocketIO(app, cors_allowed_origins="*") 

# Define WebSocket handler
@socketio.on('message')
def handle_message(message):
    print(f"Received message: {message}")
    # Echo the message back to the client
    send(f"Echo: {message}", broadcast=False)  # Respond to the sending client

# Run the Flask-SocketIO app
if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", debug=True, port=9002, allow_unsafe_werkzeug=True)
