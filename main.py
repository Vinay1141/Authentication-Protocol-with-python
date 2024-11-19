import tkinter as tk
from device import Device
from server import Server

class ProtocolApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Authentication Protocol")
        self.log_text = tk.Text(self.root, height=30, width=100)
        self.log_text.pack()

        self.device = None  # Device object will be created after registration
        self.server = Server(self.log, "Server_001", "supersecretkey12")

        self.step_label = tk.Label(self.root, text="Step: Initialize", font=("Arial", 14))
        self.step_label.pack()

        # Input fields for registration parameters
        self.reg_id_label = tk.Label(self.root, text="Registration ID:")
        self.reg_id_label.pack()
        self.reg_id_entry = tk.Entry(self.root, width=30)
        self.reg_id_entry.pack()

        self.reg_password_label = tk.Label(self.root, text="Registration Password:")
        self.reg_password_label.pack()
        self.reg_password_entry = tk.Entry(self.root, show="*", width=30)  # Password hidden
        self.reg_password_entry.pack()

        # Input fields for authentication parameters
        self.auth_id_label = tk.Label(self.root, text="Authentication ID:")
        self.auth_id_label.pack()
        self.auth_id_entry = tk.Entry(self.root, width=30)
        self.auth_id_entry.pack()

        self.auth_password_label = tk.Label(self.root, text="Authentication Password:")
        self.auth_password_label.pack()
        self.auth_password_entry = tk.Entry(self.root, show="*", width=30)  # Password hidden
        self.auth_password_entry.pack()

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

        # Retrieve input values for registration
        reg_id = self.reg_id_entry.get()
        reg_password = self.reg_password_entry.get()

        if not reg_id or not reg_password:
            self.log("[Error] Both Registration ID and Password must be provided.")
            return

        try:
            # Create a new device object
            self.device = Device(self.log, reg_id, reg_password)

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
            self.log(f"[Error] Registration failed: {e}")

    def authenticate_device(self):
        self.step_label.config(text="Step: Device Authentication")
        self.log("[Protocol] Starting Device Authentication...")

        # Retrieve input values
        auth_id = self.auth_id_entry.get()
        auth_password = self.auth_password_entry.get()

        if not auth_id or not auth_password:
            self.log("[Error] Both Authentication ID and Password must be provided.")
            return

        try:
            # Step 1: Device starts authentication
            server_public_key = self.server.ecc_public_key
            Ni, T1, Ei, iv = self.device.start_authentication(server_public_key, auth_id, auth_password)
            self.log(f"[Device] Sent authentication request with T1: {T1} and IV: {iv.hex()}")

            # Step 2: Server processes the authentication request
            pid_i = self.device.stored_data['Pid_i']
            response = self.server.process_auth_request(pid_i, Ni, T1, Ei, iv)
            if not response:
                self.log("[Server] Authentication failed during T1 validation.")
                return

            # Step 3: Device processes the server's response
            Ti, T2, response_iv = response
            self.log(f"[Server] Sent response T2: {T2} with IV: {response_iv.hex()}")

            auth_status = self.device.process_server_response(Ti, T2, response_iv)
            if auth_status:
                self.log("[Protocol] Authentication Successful!")
            else:
                self.log("[Protocol] Authentication Failed!")
        except Exception as e:
            self.log(f"[Error] Authentication failed: {e}")

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    app = ProtocolApp()
    app.run()
