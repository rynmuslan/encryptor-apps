import os
from tkinter import *
from tkinter import filedialog, messagebox
from tkinter.ttk import Combobox

CHAR = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

#region BASE58
def Base58encryption(plain, key=None) -> bytes:
    if isinstance(plain, str):
        plain = plain.encode()
    num = int.from_bytes(plain, "little")
    result = [CHAR[0]] * (len(plain) - len(plain.lstrip(b'\x00')))
    while num > 0:
        num, rmd = divmod(num, len(CHAR))
        result.append(CHAR[(rmd + key) % len(CHAR)].encode() if key is not None else CHAR[rmd].encode())
    return b''.join(result[::-1]).decode()

def Base58decryption(compiled, key=None) -> str:
        if isinstance(compiled, bytes):
            compiled = compiled.decode()
        num = 0
        for Char in compiled.rstrip(CHAR[0]):
            num = num * len(CHAR) + (CHAR.index(Char) - key) % len(CHAR) if key is not None else num * len(CHAR) + CHAR.index(Char)
        return ((b'\x00' * (len(compiled) - len(compiled.lstrip(CHAR[0])))) + num.to_bytes((num.bit_length() + 7) >> 3, "little")).decode()
#endregion

def readfile():
    global filepath
    filepath = filedialog.askopenfilename()   
    with open(filepath, 'rb') as file:
            binary_content = file.read()
            file_label.config(text=f"File Location: {filepath}")
            textbox_file.delete(1.0, END)
            textbox_file.insert(END, binary_content)
            button_delete_file.config(state=NORMAL)
            
def savefile():
    global filepath
    filepath = filedialog.asksaveasfilename(defaultextension=".bin", filetypes=[("Binary files", "*.bin"), ("All files", "*.*")])
    with open(filepath, 'wb') as file:
            binary_content = textbox_file.get("1.0", END).encode('utf-8')
            file.write(binary_content)
            file_label.config(text=f"File Location: {filepath}")
            button_delete_file.config(state=NORMAL)
            
def deletefile():
    global filepath
    if filepath:
        confirmation = messagebox.askyesno("Delete Confirmation", f"Are you sure you want to delete {os.path.basename(filepath)}?")
        if confirmation:
            os.remove(filepath)
            file_label.config(text="File Location: ")
            textbox_file.delete(1.0, END)
            button_delete_file.config(state=DISABLED)

def fileprocessing(mode, c=None):
    def convert_key(key):
        return sum(ord(CHAR) for CHAR in key)

    if mode == 1:
        # Get the content from the first character to the end (excluding the newline at the end)
        file_content = textbox_file.get("1.0", END).encode()
        encoded_text = Base58encryption(file_content, convert_key(c))
        textbox_file.delete(1.0, END)
        textbox_file.insert(END, encoded_text)

         
    
    

app = Tk()
app.title("FILES ENCRYPTION")

# set position & size GUI
screen_width = app.winfo_screenwidth()
screen_height = app.winfo_screenheight()
app.geometry(f"905x368+{(screen_width - 905) // 2}+{(screen_height - 368) // 2}")
app.resizable(False, False)

# set interface navigation
file_label = Label(app, text="File Location: ")
file_label.grid(row=0, column=0, pady=(10, 5), padx=10)

textbox_file = Text(app, height=10, width=110)
textbox_file.grid(row=1, column=0, pady=(0, 10), padx=10)

# set button navigation
button_read_file = Button(app, text="Get File", command=lambda: readfile(), width=40, height=2)
button_read_file.grid(row=2, column=0, sticky="w", pady=(0, 10), padx=10)

button_save_file = Button(app, text="Save", command=lambda: savefile(), width=40, height=2)
button_save_file.grid(row=2, column=0, sticky="s", pady=(0, 10), padx=10)

button_delete_file = Button(app, text="Delete", command=lambda: deletefile(), width=40, height=2, state=DISABLED)
button_delete_file.grid(row=2, column=0, sticky="e", pady=(0, 10), padx=10)

# set Encoder option
label_encoder = Label(app, text="Select Encoder  :")
label_encoder.grid(row=3, column=0, sticky="w", pady=(0, 10), padx=10)

options = ["Base58"]
combo_var = StringVar(value=options[0])
combo = Combobox(app, values=options, textvariable=combo_var)
combo.grid(row=3, column=0, sticky="w", pady=(0, 10), padx=105)

# set method encoding
label_radio = Label(app, text="Select Mode  :")
label_radio.grid(row=3, column=0, sticky="w", pady=(0, 10), padx=325)

radio_var = IntVar()
radio_var.set(1)  # Set default selection
radio_Encode = Radiobutton(app, text="Encode", variable=radio_var, value=1)
radio_Encode.grid(row=3, column=0, sticky="s", pady=(0, 30), padx=0)

radio_Decode = Radiobutton(app, text="Decode", variable=radio_var, value=2)
radio_Decode.grid(row=3, column=0, sticky="s", pady=(0, 10), padx=0)

# set cipher
label_radio = Label(app, text="Set your Cipher  :")
label_radio.grid(row=3, column=0, sticky="e", pady=(0, 10), padx=205)

textbox_cipher = Text(app, height=1, width=23)
textbox_cipher.grid(row=3, column=0, sticky="e", pady=(0, 10), padx=10)

button_execute = Button(app, text="PROCESS", command=lambda: fileprocessing(radio_var,textbox_cipher), width=125, height=2)
button_execute.grid(row=5, column=0, sticky="S", pady=(0, 10), padx=10)

app.mainloop()
