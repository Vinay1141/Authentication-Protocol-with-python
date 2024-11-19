import tkinter as tk
from device import Device
from server import Server

class ProtocolApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("IoT Authentication Protocol")
        self.log_text = tk.Text(self.root, height=30, width=240)
        self.log_text.pack()

        # Device and Server Instances
        self.server = Server(self.log, "cloudserver_id_1", "supersecretkey12")
        self.device = None  # Device will be initialized during registration

        # Step Indicator
        self.step_label = tk.Label(self.root, text="Step: Initialize", font=("Arial", 14))
        self.step_label.pack()

        # Input fields for Registration
        self.register_id_label = tk.Label(self.root, text="Device ID:")
        self.register_id_label.pack()
        self.register_id_entry = tk.Entry(self.root, width=30)
        self.register_id_entry.pack()

        self.register_password_label = tk.Label(self.root, text="Password:")
        self.register_password_label.pack()
        self.register_password_entry = tk.Entry(self.root, show="*", width=30)
        self.register_password_entry.pack()

        self.register_button = tk.Button(
            self.root, text="Register Device", command=self.register_device, state=tk.NORMAL
        )
        self.register_button.pack(pady=10)

        # Input fields for Authentication
        self.auth_id_label = tk.Label(self.root, text="Device ID (Authentication):")
        self.auth_id_label.pack()
        self.auth_id_entry = tk.Entry(self.root, width=30)
        self.auth_id_entry.pack()

        self.auth_password_label = tk.Label(self.root, text="Password (Authentication):")
        self.auth_password_label.pack()
        self.auth_password_entry = tk.Entry(self.root, show="*", width=30)
        self.auth_password_entry.pack()

        self.authenticate_button = tk.Button(
            self.root, text="Authenticate Device", command=self.authenticate_device, state=tk.DISABLED
        )
        self.authenticate_button.pack(pady=10)

    def log(self, message):
        """Logs messages to the GUI."""
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.see(tk.END)

    def register_device(self):
        """Handles device registration."""
        device_id = self.register_id_entry.get()
        password = self.register_password_entry.get()

        if not device_id or not password:
            self.log("[Error] Both Device ID and Password are required for registration.")
            return

        self.log("[Protocol] Starting Device Registration...")
        self.device = Device(self.log, device_id, password)

        # Device generates identifier
        I_i = self.device.generate_identifier()
        self.log(f"[Device] Generated Identifier: {I_i}")

        # Server processes registration
        Ii, Pid_i, A_prime_i, R_prime_i, C_k = self.server.register_device(I_i)
        self.device.store_registration_data(Pid_i, A_prime_i, R_prime_i, C_k)
        self.log("[Device] Registration completed. Device data stored successfully.")

        # Enable authentication button
        self.authenticate_button.config(state=tk.NORMAL)
        self.log("[Protocol] Registration phase complete. Ready for authentication.")

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
            device_public_key = self.device.ecc_public_key
            response = self.server.process_auth_request(device_public_key, Ni, T1, Ei, iv)
            self.log(f"[Protocol] {response}")
            if not response:
                self.log("[Server] Authentication failed during T1 validation.")
                return

            # Step 3: Device processes the server's response
            Ti, T2, response_iv = response
            self.log(f"[Server] Sent response T2: {T2} with IV: {response_iv.hex()}")

            MN_i, Pid_i, T3 = self.device.process_server_response(Ti, T2, response_iv)
            if MN_i:
                self.log(f"[Protocol] MN_i: {MN_i.hex()} Pid_i: {Pid_i.hex()}")
                
                auth_results = self.server.final_check(MN_i, Pid_i, T3)
                if auth_results:
                    self.log(f"[Protocol] Authentication successful for device {self.device.device_id}")

            else:
                self.log("[Protocol] Authentication Failed!")
        except Exception as e:
            self.log(f"[Error] Authentication failed: {e}")


    def run(self):
        """Runs the Tkinter app."""
        self.root.mainloop()


if __name__ == "__main__":
    app = ProtocolApp()
    app.run()
