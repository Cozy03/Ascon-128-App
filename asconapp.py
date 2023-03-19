import tkinter as tk
from tkinter import filedialog
from cryptography.fernet import Fernet
from ascon import *

def encrypt(ad,pt,k,n):
    variant="Ascon-128"
    keysize=16
    # ad=bytes(ad,'utf-8')
    # k=bytes(k,'utf-8')
    # n=bytes(n,'utf-8')
    ciphertext = ascon_encrypt(k, n, ad, pt,  variant)
    return ciphertext.hex()

def decrypt(ad,ct,k,n):
    variant="Ascon-128"
    keysize=16
    ct=bytes.fromhex(ct)
    plaintext = ascon_decrypt(k, n, ad, ct,  variant)
    return plaintext.decode('utf-8')

class Application(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        self.master.title("Text File Encryptor using ASCON-128")
        self.pack()
        self.create_widgets()

    def create_widgets(self):
        self.file_label = tk.Label(self, text="Select a .txt file to encrypt/decrypt:")
        self.file_label.pack()

        self.file_button = tk.Button(self, text="Choose File", command=self.choose_file)
        self.file_button.pack()

        self.ad_label = tk.Label(self, text="Enter the Associated Data:")
        self.ad_label.pack()

        self.ad_entry = tk.Entry(self)
        self.ad_entry.pack()

        self.key_label = tk.Label(self, text="Enter the encryption/decryption key(16 Characters Long):")
        self.key_label.pack()

        self.key_entry = tk.Entry(self)
        self.key_entry.pack()

        self.nonce_label = tk.Label(self, text="Enter the encryption/decryption nonce(16 Characters Long):")
        self.nonce_label.pack()

        self.nonce_entry = tk.Entry(self)
        self.nonce_entry.pack()

        self.mode_label = tk.Label(self, text="Select a mode:")
        self.mode_label.pack()

        self.mode_var = tk.StringVar(value="encrypt")

        self.encrypt_radio = tk.Radiobutton(self, text="Encrypt", variable=self.mode_var, value="encrypt", command=self.update_mode)
        self.encrypt_radio.pack()

        self.decrypt_radio = tk.Radiobutton(self, text="Decrypt", variable=self.mode_var, value="decrypt", command=self.update_mode)
        self.decrypt_radio.pack()

        self.text_label = tk.Label(self, text="Output text:")
        self.text_label.pack()

        self.text_box = tk.Text(self)
        self.text_box.pack()

        self.process_button = tk.Button(self, text="Encrypt/Decrypt", command=self.process_file, state=tk.DISABLED)
        self.process_button.pack()

        self.download_button = tk.Button(self, text="Download Output", command=self.download_file, state=tk.DISABLED)
        self.download_button.pack()

    def choose_file(self):
        filetypes = (("Text files", "*.txt"), ("All files", "*.*"))
        filename = filedialog.askopenfilename(title="Select a file", filetypes=filetypes)
        if filename:
            self.filename = filename
            self.file_label.config(text="Selected file: {}".format(self.filename))
            self.process_button.config(state=tk.NORMAL)

    def update_mode(self):
        mode = self.mode_var.get()
        if mode == "encrypt":
            self.file_label.config(text="Select a .txt file to encrypt:")
            self.process_button.config(text="Encrypt")
        elif mode == "decrypt":
            self.file_label.config(text="Select a .txt file to decrypt:")
            self.process_button.config(text="Decrypt")

    def process_file(self):
        mode = self.mode_var.get()
        if mode == "encrypt":
            with open(self.filename, "rb") as f:
                data = f.read()

        elif mode=="decrypt":
            with open(self.filename, "r") as f:
                data = f.read()


        ad=self.ad_entry.get().encode('utf-8')
        key = self.key_entry.get().encode('utf-8')
        nonce = self.nonce_entry.get().encode('utf-8')

        # fernet = Fernet(key)

        if mode == "encrypt":
            output_data=encrypt(ad,data,key,nonce)
            # output_data = fernet.encrypt(data, nonce=nonce)
        elif mode == "decrypt":
            output_data=decrypt(ad,data,key,nonce)
            print(output_data)
            # output_data = fernet.decrypt(data, nonce=nonce)

        self.text_box.delete("1.0", tk.END)
        self.text_box.insert(tk.END, output_data)

        self.file_label.config(text="Select a .txt file to encrypt/decrypt:")
        self.process_button.config(state=tk.DISABLED)

        self.download_button.config(state=tk.NORMAL)
    def download_file(self):
        content = self.text_box.get("1.0", "end-1c")
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if file_path:
            with open(file_path, "w") as f:
                f.write(content)

root = tk.Tk()
app = Application(master=root)
app.mainloop()