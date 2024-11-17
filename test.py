# Test script to simulate registration and authentication

from device import Device
from server import Server

# Initialize server
server = Server()

# Initialize device and register
device = Device(device_id="device123", password="securepass")
device_identifier = device.register()
server_data = server.register_device(device.device_id, device_identifier)

# Device receives session key from server
device.receive_registration_info(server_data)

# Device authenticates with server
iv, encrypted_message, tag = device.authenticate()
auth_status = server.authenticate_device(device.device_id, iv, encrypted_message, tag)

if auth_status:
    print("Authentication successful!")
else:
    print("Authentication failed.")
