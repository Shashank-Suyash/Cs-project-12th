import os
import re
import random
import string
import hashlib
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import messagebox, simpledialog, scrolledtext


def generate_key():
    key = Fernet.generate_key()
    with open("encryption.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    return open("encryption.key", "rb").read()

# --------------------------
# Password encryption/decryption
# --------------------------
def encrypt_data(data, key):
    f = Fernet(key)
    return f.encrypt(data.encode())

def decrypt_data(encrypted_data, key):
    f = Fernet(key)
    return f.decrypt(encrypted_data).decode()

# --------------------------
# Master password functions
# --------------------------
def set_master_password():
    if not os.path.exists("master.txt"):
        while True:
            master_password = simpledialog.askstring("Set Master Password", "Set a master password:", show='*')
            if not master_password:
                messagebox.showerror("Error", "Master password cannot be empty.")
                continue
            confirm = simpledialog.askstring("Confirm Master Password", "Confirm master password:", show='*')
            if master_password != confirm:
                messagebox.showerror("Error", "Passwords do not match. Try again.")
            else:
                break
        hashed_master_password = hashlib.sha256(master_password.encode()).hexdigest()
        with open("master.txt", "w") as file:
            file.write(hashed_master_password)
        messagebox.showinfo("Success", "Master password set successfully.")
    else:
        messagebox.showinfo("Info", "Master password already set.")

def verify_master_password():
    if os.path.exists("master.txt"):
        with open("master.txt", "r") as file:
            stored_hashed_master_password = file.read()
        for _ in range(3):
            master_password = simpledialog.askstring("Master Password", "Enter the master password:", show='*')
            if not master_password:
                return False
            hashed_master_password = hashlib.sha256(master_password.encode()).hexdigest()
            if hashed_master_password == stored_hashed_master_password:
                messagebox.showinfo("Success", "Master password verified.")
                return True
            else:
                messagebox.showerror("Error", "Incorrect master password.")
        return False
    else:
        messagebox.showinfo("Info", "No master password found. Please set it up first.")
        set_master_password()
        return False

# --------------------------
# Password strength checker
# --------------------------
def check_password_strength(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search("[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search("[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search("[0-9]", password):
        return False, "Password must contain at least one digit."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character."
    return True, "Password is strong."

# --------------------------
# Password file operations
# --------------------------
def add_password(account, password):
    is_strong, message = check_password_strength(password)
    if not is_strong:
        messagebox.showerror("Weak Password", message)
        return
    key = load_key()
    encrypted_password = encrypt_data(password, key)
    with open("passwords.txt", "a") as file:
        file.write(f"{account}:{encrypted_password.decode()}\n")
    messagebox.showinfo("Success", f"Password for {account} added successfully.")

def get_password(account):
    key = load_key()
    if not os.path.exists("passwords.txt"):
        return None
    with open("passwords.txt", "r") as file:
        for line in file:
            stored_account, stored_encrypted_password = line.strip().split(":")
            if stored_account == account:
                return decrypt_data(stored_encrypted_password.encode(), key)
    return None

def delete_password(account):
    if not os.path.exists("passwords.txt"):
        messagebox.showerror("Error", "No passwords file found.")
        return
    lines = []
    found = False
    with open("passwords.txt", "r") as file:
        for line in file:
            stored_account = line.strip().split(":")[0]
            if stored_account != account:
                lines.append(line)
            else:
                found = True
    if found:
        with open("passwords.txt", "w") as file:
            file.writelines(lines)
        messagebox.showinfo("Success", f"Password for {account} deleted successfully.")
    else:
        messagebox.showinfo("Info", f"No password found for account: {account}")

def list_accounts():
    if not os.path.exists("passwords.txt"):
        messagebox.showinfo("Info", "No passwords saved yet.")
        return []
    with open("passwords.txt", "r") as file:
        accounts = [line.strip().split(":")[0] for line in file]
    return accounts

# --------------------------
# Backup and restore functions
# --------------------------
def backup_passwords():
    if os.path.exists("passwords.txt"):
        with open("passwords.txt", "r") as original_file, open("passwords_backup.txt", "w") as backup_file:
            for line in original_file:
                backup_file.write(line)
        messagebox.showinfo("Success", "Backup completed successfully.")
    else:
        messagebox.showinfo("Info", "No passwords file found to backup.")

def restore_passwords():
    if os.path.exists("passwords_backup.txt"):
        with open("passwords_backup.txt", "r") as backup_file, open("passwords.txt", "w") as original_file:
            for line in backup_file:
                original_file.write(line)
        messagebox.showinfo("Success", "Passwords restored from backup.")
    else:
        messagebox.showinfo("Info", "No backup file found to restore.")

# --------------------------
# Random password generator
# --------------------------
def generate_random_password(length=12):
    characters = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:,.<>/?"
    random_password = ''.join(random.choice(characters) for _ in range(length))
    return random_password

# --------------------------
# GUI App class
# --------------------------
class PasswordManagerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Password Manager")
        self.geometry("500x400")
        self.resizable(False, False)

        # Main menu buttons
        btn_add = tk.Button(self, text="Add Password", width=20, command=self.add_password_gui)
        btn_add.pack(pady=5)

        btn_get = tk.Button(self, text="Get Password", width=20, command=self.get_password_gui)
        btn_get.pack(pady=5)

        btn_delete = tk.Button(self, text="Delete Password", width=20, command=self.delete_password_gui)
        btn_delete.pack(pady=5)

        btn_list = tk.Button(self, text="List Accounts", width=20, command=self.list_accounts_gui)
        btn_list.pack(pady=5)

        btn_generate = tk.Button(self, text="Generate Random Password", width=20, command=self.generate_password_gui)
        btn_generate.pack(pady=5)

        btn_backup = tk.Button(self, text="Backup Passwords", width=20, command=backup_passwords)
        btn_backup.pack(pady=5)

        btn_restore = tk.Button(self, text="Restore Passwords", width=20, command=restore_passwords)
        btn_restore.pack(pady=5)

        btn_exit = tk.Button(self, text="Exit", width=20, command=self.quit)
        btn_exit.pack(pady=5)

    # Add password GUI
    def add_password_gui(self):
        account = simpledialog.askstring("Add Password", "Enter account name:")
        if not account:
            return
        password = simpledialog.askstring("Add Password", "Enter password:", show='*')
        if not password:
            return
        add_password(account, password)

    # Get password GUI
    def get_password_gui(self):
        account = simpledialog.askstring("Get Password", "Enter account name:")
        if not account:
            return
        password = get_password(account)
        if password:
            messagebox.showinfo("Password Found", f"Password for {account}: {password}")
        else:
            messagebox.showinfo("Not Found", "No password found for that account.")

    # Delete password GUI
    def delete_password_gui(self):
        account = simpledialog.askstring("Delete Password", "Enter account name:")
        if not account:
            return
        delete_password(account)

    # List accounts GUI
    def list_accounts_gui(self):
        accounts = list_accounts()
        if not accounts:
            messagebox.showinfo("Accounts", "No accounts found.")
            return
        list_win = tk.Toplevel(self)
        list_win.title("Accounts")
        list_win.geometry("300x300")
        text_area = scrolledtext.ScrolledText(list_win, width=35, height=15)
        text_area.pack(padx=10, pady=10)
        text_area.insert(tk.END, "\n".join(accounts))
        text_area.config(state='disabled')

    # Generate random password GUI
    def generate_password_gui(self):
        length = simpledialog.askinteger("Random Password", "Enter desired length (default 12):", minvalue=6, maxvalue=64)
        if not length:
            length = 12
        random_password = generate_random_password(length)
        messagebox.showinfo("Generated Password", random_password)

# --------------------------
# Main function
# --------------------------
def main():
    if not os.path.exists("encryption.key"):
        generate_key()

    set_master_password()

    if not verify_master_password():
        messagebox.showerror("Error", "Master password verification failed. Exiting.")
        return

    app = PasswordManagerApp()
    app.mainloop()

if __name__ == "__main__":
    main()
