import tkinter as tk
from device import Device
from server import Server


class ProtocolApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Authentication Protocol")
        self.log_text = tk.Text(self.root, height=30, width=100)
        self.log_text.pack()

        self.device = Device(self.log, "Device_001", "securepassword123")
        self.server = Server(self.log, "Server_001", "supersecretkey12")

        self.step_label = tk.Label(self.root, text="Step: Initialize", font=("Arial", 14))
        self.step_label.pack()

        self.register_button = tk.Button(
            self.root, text="Register Device", command=self.register_device, state=tk.NORMAL
        )
        self.register_button.pack(pady=10)

        self.authenticate_button = tk.Button(
            self.root, text="Authenticate Device", command=self.authenticate_device, state=tk.DISABLED
        )
        self.authenticate_button.pack(pady=10)

    def log(self, message):
        """Log messages to the GUI."""
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.see(tk.END)

    def register_device(self):
        self.step_label.config(text="Step: Device Registration")
        self.log("[Protocol] Starting Device Registration...")

        try:
            # Step 1: Device generates an identifier
            identifier = self.device.generate_identifier()
            self.log(f"[Device] Identifier I_i generated: {identifier}")

            # Step 2: Server processes registration request
            pid_i, a_prime_i, r_prime_i, c_prime_k = self.server.register_device(identifier)
            self.log("[Server] Registration request processed. Returning data to device.")

            # Step 3: Device stores registration data
            self.device.store_registration_data(pid_i, a_prime_i, r_prime_i, c_prime_k)
            session_key = self.server.database[pid_i]['Session_Key']  # Retrieve session key
            self.device.set_session_key(session_key)
            self.log(f"[Device] Session key set: {session_key.hex()}")
            self.log("[Device] Registration data stored successfully.")

            # Enable the "Authenticate Device" button
            self.authenticate_button.config(state=tk.NORMAL)
            self.log("[Protocol] Registration completed. Ready for authentication.")
        except Exception as e:
            self.log(e)
            self.log(f"[Error] Registration failed: {e}")

    def authenticate_device(self):
        self.step_label.config(text="Step: Device Authentication")
        self.log("[Protocol] Starting Device Authentication...")

        # Step 1: Device generates T1 and sends it to the server
        Ni, T1, Ei, iv = self.device.start_authentication()
        self.log(f"[Device] Sent encrypted T1: {T1} with IV: {iv.hex()}")
        self.log(f"Device Identifier: {self.device.stored_data['Pid_i']}")
        # Step 2: Server processes T1 and responds with T2
        response = self.server.process_auth_request(self.device.stored_data['Pid_i'], Ni, T1, Ei, iv)
        if not response:
            self.log("[Server] Authentication failed during T1 validation.")
            return

        S_i, R_e, response_iv = response
        self.log(f"[Server] Sent encrypted T2: {encrypted_T2.hex()} with IV: {response_iv.hex()}")

        # Step 3: Device processes T2 and completes authentication
        auth_status = self.device.process_server_response(encrypted_T2, response_iv)
        if auth_status:
            self.log("[Protocol] Authentication Successful!")
        else:
            self.log("[Protocol] Authentication Failed!")

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    app = ProtocolApp()
    app.run()
