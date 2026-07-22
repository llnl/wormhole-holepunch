import time
import socketio

# Initialize a Socket.IO client
sio = socketio.Client()

# Define the message reception event
@sio.on('message')
def on_message(data):
    print(f"Received: {data}")

headers = {
    "X-Token": "foo",
}
sio.connect("http://localhost:3128", headers=headers, transports=["websocket"])

print("Starting to send messages...")

# Send 30 incrementing messages, one every second
for i in range(1, 31):  # Loop from 1 to 30 (inclusive)
    message = f"Message {i}"
    print(f"Sending: {message}")
    sio.send(message)
    time.sleep(1)  # Wait for 1 second

print("Finished sending messages.")
sio.disconnect()
