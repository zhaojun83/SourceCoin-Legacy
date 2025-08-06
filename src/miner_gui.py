import os
import json
import requests
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import threading
import time
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet, InvalidToken
import base64
import hashlib
from imports.consts import WALLET_FILE, API_URL


class SourceCoinGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SourceCoin Legacy Miner & Wallet")
        self.root.geometry("800x600")
        self.root.configure(bg='#1e1e1e')
        
        # Styling
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('Title.TLabel', font=('Arial', 16, 'bold'), background='#1e1e1e', foreground='#ffffff')
        self.style.configure('Heading.TLabel', font=('Arial', 12, 'bold'), background='#1e1e1e', foreground='#ffffff')
        self.style.configure('Info.TLabel', font=('Arial', 10), background='#1e1e1e', foreground='#cccccc')
        self.style.configure('Success.TLabel', font=('Arial', 10), background='#1e1e1e', foreground='#00ff00')
        self.style.configure('Error.TLabel', font=('Arial', 10), background='#1e1e1e', foreground='#ff0000')
        
        self.wallet = None
        self.address = None
        self.mining_active = False
        self.mining_thread = None
        
        self.setup_ui()
        self.load_wallet_auto()
    
    def derive_key(self, password: str) -> bytes:
        return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

    def encrypt_private_key(self, private_key_pem: str, password: str) -> str:
        key = self.derive_key(password)
        f = Fernet(key)
        return f.encrypt(private_key_pem.encode()).decode()

    def decrypt_private_key(self, encrypted_pem: str, password: str) -> str:
        key = self.derive_key(password)
        f = Fernet(key)
        return f.decrypt(encrypted_pem.encode()).decode()
    
    def setup_ui(self):
        # Main container
        main_frame = tk.Frame(self.root, bg='#1e1e1e')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Title
        title_label = ttk.Label(main_frame, text="SourceCoin Miner & Wallet", style='Title.TLabel')
        title_label.pack(pady=(0, 20))
        
        # Wallet Info Frame
        wallet_frame = tk.LabelFrame(main_frame, text="Wallet Information", bg='#2e2e2e', fg='#ffffff', font=('Arial', 10, 'bold'))
        wallet_frame.pack(fill=tk.X, pady=(0, 15))
        
        self.address_label = ttk.Label(wallet_frame, text="Address: Not loaded", style='Info.TLabel')
        self.address_label.pack(anchor=tk.W, padx=10, pady=5)
        
        self.balance_label = ttk.Label(wallet_frame, text="Balance: 0", style='Info.TLabel')
        self.balance_label.pack(anchor=tk.W, padx=10, pady=5)
        
        # Buttons Frame
        buttons_frame = tk.Frame(main_frame, bg='#1e1e1e')
        buttons_frame.pack(fill=tk.X, pady=(0, 15))
        
        # Wallet buttons
        wallet_buttons_frame = tk.Frame(buttons_frame, bg='#1e1e1e')
        wallet_buttons_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.create_wallet_btn = tk.Button(wallet_buttons_frame, text="Create New Wallet", 
                                         command=self.create_wallet, bg='#4CAF50', fg='white', 
                                         font=('Arial', 10, 'bold'), relief=tk.FLAT, padx=20)
        self.create_wallet_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.load_wallet_btn = tk.Button(wallet_buttons_frame, text="Load Wallet", 
                                       command=self.load_wallet, bg='#2196F3', fg='white', 
                                       font=('Arial', 10, 'bold'), relief=tk.FLAT, padx=20)
        self.load_wallet_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.refresh_balance_btn = tk.Button(wallet_buttons_frame, text="Refresh Balance", 
                                           command=self.refresh_balance, bg='#FF9800', fg='white', 
                                           font=('Arial', 10, 'bold'), relief=tk.FLAT, padx=20)
        self.refresh_balance_btn.pack(side=tk.LEFT)
        
        # Mining buttons
        mining_buttons_frame = tk.Frame(buttons_frame, bg='#1e1e1e')
        mining_buttons_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.mine_once_btn = tk.Button(mining_buttons_frame, text="Mine One Block", 
                                     command=self.mine_once, bg='#9C27B0', fg='white', 
                                     font=('Arial', 10, 'bold'), relief=tk.FLAT, padx=20)
        self.mine_once_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.start_mining_btn = tk.Button(mining_buttons_frame, text="Start Continuous Mining", 
                                        command=self.toggle_mining, bg='#F44336', fg='white', 
                                        font=('Arial', 10, 'bold'), relief=tk.FLAT, padx=20)
        self.start_mining_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Transaction button
        self.send_tx_btn = tk.Button(mining_buttons_frame, text="Send Transaction", 
                                   command=self.send_transaction_dialog, bg='#607D8B', fg='white', 
                                   font=('Arial', 10, 'bold'), relief=tk.FLAT, padx=20)
        self.send_tx_btn.pack(side=tk.LEFT)
        
        # Status Frame
        status_frame = tk.LabelFrame(main_frame, text="Mining Status", bg='#2e2e2e', fg='#ffffff', font=('Arial', 10, 'bold'))
        status_frame.pack(fill=tk.X, pady=(0, 15))
        
        self.mining_status_label = ttk.Label(status_frame, text="Mining: Stopped", style='Info.TLabel')
        self.mining_status_label.pack(anchor=tk.W, padx=10, pady=5)
        
        # Log Frame
        log_frame = tk.LabelFrame(main_frame, text="Activity Log", bg='#2e2e2e', fg='#ffffff', font=('Arial', 10, 'bold'))
        log_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create scrollable text widget
        log_scroll_frame = tk.Frame(log_frame, bg='#2e2e2e')
        log_scroll_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.log_text = tk.Text(log_scroll_frame, bg='#1e1e1e', fg='#ffffff', 
                               font=('Consolas', 9), state=tk.DISABLED, wrap=tk.WORD)
        scrollbar = tk.Scrollbar(log_scroll_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.config(yscrollcommand=scrollbar.set)
        
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Initially disable wallet-dependent buttons
        self.update_button_states()
    
    def log_message(self, message, msg_type="info"):
        timestamp = time.strftime("%H:%M:%S")
        colors = {
            "info": "#cccccc",
            "success": "#00ff00", 
            "error": "#ff0000",
            "warning": "#ffaa00"
        }
        color = colors.get(msg_type, "#cccccc")
        
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.tag_add(msg_type, f"end-2l linestart", f"end-1l lineend")
        self.log_text.tag_config(msg_type, foreground=color)
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
    
    def update_button_states(self):
        wallet_loaded = self.wallet is not None
        
        self.refresh_balance_btn.config(state=tk.NORMAL if wallet_loaded else tk.DISABLED)
        self.mine_once_btn.config(state=tk.NORMAL if wallet_loaded else tk.DISABLED)
        self.start_mining_btn.config(state=tk.NORMAL if wallet_loaded else tk.DISABLED)
        self.send_tx_btn.config(state=tk.NORMAL if wallet_loaded else tk.DISABLED)
    
    def create_wallet(self):
        password = simpledialog.askstring("Create Wallet", "Enter password for new wallet:", show='*')
        if not password:
            return
            
        confirm = simpledialog.askstring("Create Wallet", "Confirm password:", show='*')
        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match!")
            return
        
        try:
            self.log_message("Generating new wallet...", "info")
            
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            pub_key = private_key.public_key()

            priv_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption())

            pub_bytes = pub_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)

            address = hashlib.sha256(pub_bytes).hexdigest()
            encrypted_priv = self.encrypt_private_key(priv_bytes.decode(), password)

            wallet = {
                'address': address,
                'private_key': encrypted_priv,
                'public_key': pub_bytes.decode()
            }

            with open(WALLET_FILE, 'w') as f:
                json.dump(wallet, f)
            
            self.wallet = wallet
            self.wallet['private_key'] = priv_bytes.decode()  # Decrypt for use
            self.address = address
            
            self.address_label.config(text=f"Address: {address[:20]}...")
            self.log_message(f"New wallet created! Address: {address}", "success")
            self.update_button_states()
            self.refresh_balance()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create wallet: {str(e)}")
            self.log_message(f"Failed to create wallet: {str(e)}", "error")
    
    def load_wallet_auto(self):
        if os.path.exists(WALLET_FILE):
            self.load_wallet()
    
    def load_wallet(self):
        if not os.path.exists(WALLET_FILE):
            messagebox.showwarning("Warning", "No wallet file found. Please create a new wallet.")
            return
        
        password = simpledialog.askstring("Load Wallet", "Enter wallet password:", show='*')
        if not password:
            return
        
        try:
            with open(WALLET_FILE, 'r') as f:
                wallet = json.load(f)
            
            decrypted_priv = self.decrypt_private_key(wallet['private_key'], password)
            wallet['private_key'] = decrypted_priv
            
            self.wallet = wallet
            self.address = self.get_address(wallet['public_key'])
            
            self.address_label.config(text=f"Address: {self.address[:20]}...")
            self.log_message(f"Wallet loaded! Address: {self.address}", "success")
            self.update_button_states()
            self.refresh_balance()
            
        except InvalidToken:
            messagebox.showerror("Error", "Wrong password!")
            self.log_message("Wrong wallet password", "error")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load wallet: {str(e)}")
            self.log_message(f"Failed to load wallet: {str(e)}", "error")
    
    def get_address(self, pub_key_pem):
        return hashlib.sha256(pub_key_pem.encode()).hexdigest()
    
    def refresh_balance(self):
        if not self.address:
            return
        
        try:
            r = requests.get(f'{API_URL}/balance/{self.address}', timeout=10)
            if r.status_code == 200:
                try:
                    balance = r.json().get('balance', 0)
                    self.balance_label.config(text=f"Balance: {balance}")
                    self.log_message(f"Balance updated: {balance}", "info")
                except ValueError:
                    self.log_message(f"Invalid balance response: {r.text[:50]}", "error")
            else:
                self.log_message(f"Error getting balance (HTTP {r.status_code})", "error")
        except requests.exceptions.ConnectionError:
            self.log_message("Cannot connect to server for balance check", "error")
        except Exception as e:
            self.log_message(f"Error refreshing balance: {str(e)}", "error")
    
    def mine_once(self):
        if not self.address:
            return
        
        def mine_thread():
            try:
                self.log_message("Mining block...", "info")
                r = requests.get(f'{API_URL}/mine', params={'miner': self.address}, timeout=30)
                
                self.log_message(f"Mining response status: {r.status_code}", "info")
                
                if r.status_code == 200:
                    try:
                        data = r.json()
                        self.log_message(f"Successfully mined block! Reward: {data['reward']}", "success")
                        self.root.after(0, self.refresh_balance)
                    except ValueError as json_error:
                        self.log_message(f"Invalid JSON response: {r.text[:100]}", "error")
                elif r.status_code == 429:
                    try:
                        data = r.json()
                        error_msg = data.get('message', 'Rate limited - try again later')
                        self.log_message(f"Mining rate limited: {error_msg}", "warning")
                        self.log_message("Wait 10-20 minutes before mining again (blockchain protection)", "warning")
                    except ValueError:
                        self.log_message(f"Mining rate limited (HTTP 429): {r.text[:100]}", "warning")
                        self.log_message("Wait 10-20 minutes before mining again (blockchain protection)", "warning")
                else:
                    try:
                        error_msg = r.json().get('message', f'HTTP {r.status_code} error')
                        self.log_message(f"Mining error: {error_msg}", "error")
                    except ValueError:
                        self.log_message(f"Mining error (HTTP {r.status_code}): {r.text[:100]}", "error")
                        
            except requests.exceptions.Timeout:
                self.log_message("Mining request timed out - server may be processing", "warning")
            except requests.exceptions.ConnectionError:
                self.log_message("Cannot connect to blockchain server - is it running?", "error")
            except Exception as e:
                self.log_message(f"Error during mining: {str(e)}", "error")
        
        threading.Thread(target=mine_thread, daemon=True).start()
    
    def toggle_mining(self):
        if self.mining_active:
            self.stop_mining()
        else:
            self.start_mining()
    
    def start_mining(self):
        if not self.address:
            return
        
        self.mining_active = True
        self.start_mining_btn.config(text="Stop Mining", bg='#4CAF50')
        self.mining_status_label.config(text="Mining: Active")
        
        def continuous_mining():
            while self.mining_active:
                try:
                    self.log_message("Mining block...", "info")
                    r = requests.get(f'{API_URL}/mine', params={'miner': self.address}, timeout=30)
                    
                    if r.status_code == 200:
                        try:
                            data = r.json()
                            self.log_message(f"Successfully mined block! Reward: {data['reward']}", "success")
                            self.root.after(0, self.refresh_balance)
                        except ValueError as json_error:
                            self.log_message(f"Invalid JSON response: {r.text[:100]}", "error")
                            time.sleep(5)
                    elif r.status_code == 429:
                        try:
                            data = r.json()
                            error_msg = data.get('message', 'Rate limited - waiting...')
                            self.log_message(f"Mining rate limited: {error_msg}", "warning")
                            self.log_message("⏰ Waiting 10 minutes before next attempt...", "warning")
                        except ValueError:
                            self.log_message("Mining rate limited - waiting...", "warning")
                            self.log_message("⏰ Waiting 10 minutes before next attempt...", "warning")
                        time.sleep(600)  # Wait 10 minutes for rate limit
                    else:
                        try:
                            error_msg = r.json().get('message', f'HTTP {r.status_code} error')
                            self.log_message(f"Mining error: {error_msg}", "error")
                        except ValueError:
                            self.log_message(f"Mining error (HTTP {r.status_code}): {r.text[:100]}", "error")
                        time.sleep(5)
                        
                except requests.exceptions.Timeout:
                    self.log_message("Mining request timed out - retrying...", "warning")
                    time.sleep(5)
                except requests.exceptions.ConnectionError:
                    self.log_message("Cannot connect to blockchain server - retrying in 10s...", "error")
                    time.sleep(10)
                except Exception as e:
                    self.log_message(f"Error during mining: {str(e)}", "error")
                    time.sleep(5)
        
        self.mining_thread = threading.Thread(target=continuous_mining, daemon=True)
        self.mining_thread.start()
        self.log_message("Continuous mining started", "success")
    
    def stop_mining(self):
        self.mining_active = False
        self.start_mining_btn.config(text="Start Continuous Mining", bg='#F44336')
        self.mining_status_label.config(text="Mining: Stopped")
        self.log_message("Mining stopped", "warning")
    
    def send_transaction_dialog(self):
        if not self.wallet:
            return
        
        # Create transaction dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("Send Transaction")
        dialog.geometry("400x300")
        dialog.configure(bg='#1e1e1e')
        dialog.resizable(False, False)
        
        # Center the dialog
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Receiver address
        tk.Label(dialog, text="Receiver Address:", bg='#1e1e1e', fg='#ffffff', font=('Arial', 10, 'bold')).pack(pady=10)
        receiver_entry = tk.Entry(dialog, width=50, bg='#2e2e2e', fg='#ffffff', font=('Consolas', 9))
        receiver_entry.pack(pady=5)
        
        # Amount
        tk.Label(dialog, text="Amount:", bg='#1e1e1e', fg='#ffffff', font=('Arial', 10, 'bold')).pack(pady=(20, 5))
        amount_entry = tk.Entry(dialog, width=20, bg='#2e2e2e', fg='#ffffff', font=('Arial', 10))
        amount_entry.pack(pady=5)
        
        # Fee
        tk.Label(dialog, text="Fee (default: 80):", bg='#1e1e1e', fg='#ffffff', font=('Arial', 10, 'bold')).pack(pady=(20, 5))
        fee_entry = tk.Entry(dialog, width=20, bg='#2e2e2e', fg='#ffffff', font=('Arial', 10))
        fee_entry.insert(0, "80")
        fee_entry.pack(pady=5)
        
        def send_tx():
            try:
                receiver = receiver_entry.get().strip()
                amount = float(amount_entry.get())
                fee = float(fee_entry.get())
                
                if not receiver or amount <= 0 or fee < 0:
                    messagebox.showerror("Error", "Please enter valid values")
                    return
                
                signature = self.sign_transaction(self.wallet['private_key'], self.address, receiver, amount, fee)
                
                tx = {
                    'sender': self.address,
                    'receiver': receiver,
                    'amount': amount,
                    'fee': fee,
                    'public_key': self.wallet['public_key'],
                    'signature': signature
                }
                
                r = requests.post(f'{API_URL}/send', json=tx)
                if r.status_code == 201:
                    self.log_message(f"Transaction sent! Amount: {amount}, Fee: {fee}", "success")
                    dialog.destroy()
                    self.refresh_balance()
                else:
                    error_msg = r.json().get('message', 'Unknown error')
                    messagebox.showerror("Error", f"Transaction failed: {error_msg}")
                    self.log_message(f"Transaction failed: {error_msg}", "error")
                    
            except ValueError:
                messagebox.showerror("Error", "Please enter valid numbers")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to send transaction: {str(e)}")
                self.log_message(f"Transaction error: {str(e)}", "error")
        
        # Buttons
        button_frame = tk.Frame(dialog, bg='#1e1e1e')
        button_frame.pack(pady=20)
        
        send_btn = tk.Button(button_frame, text="Send", command=send_tx, 
                           bg='#4CAF50', fg='white', font=('Arial', 10, 'bold'), 
                           relief=tk.FLAT, padx=20)
        send_btn.pack(side=tk.LEFT, padx=5)
        
        cancel_btn = tk.Button(button_frame, text="Cancel", command=dialog.destroy, 
                             bg='#F44336', fg='white', font=('Arial', 10, 'bold'), 
                             relief=tk.FLAT, padx=20)
        cancel_btn.pack(side=tk.LEFT, padx=5)
    
    def sign_transaction(self, private_key_pem, sender, receiver, amount, fee):
        private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
        message = f"{sender}{receiver}{amount}{fee}".encode()
        signature = private_key.sign(
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return signature.hex()


def main():
    root = tk.Tk()
    app = SourceCoinGUI(root)
    root.mainloop()


if __name__ == '__main__':
    main()
