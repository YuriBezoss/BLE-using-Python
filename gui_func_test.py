import tkinter

font_setting = ("courier", 10, "bold")
pad_setting = 10

class MyButton(tkinter.Button):
    def __init__(self, parent=None, **config):
        tkinter.Button.__init__(self, parent, **config)
        self.grid(sticky="nsew", padx=pad_setting, pady=pad_setting)
        self.config(bg="steel blue")
        self.config(font=font_setting)
        self.config(state="disabled")
    
class MyEntry(tkinter.Entry):
    def __init__(self, parent=None, **config):
        tkinter.Entry.__init__(self, parent, **config)
        self.grid(sticky="nsew", padx=pad_setting, pady=pad_setting)
        self.config(bg="light steel blue")
        self.config(font=font_setting)

class MyScrolledText(tkinter.Frame):
    def __init__(self, parent=None, text='', height=0, width=0, **config):
        tkinter.Frame.__init__(self, parent, **config)
        self.grid(sticky="nsew", ipadx=pad_setting, ipady=pad_setting)
        sbar = tkinter.Scrollbar(self)
        self.height = height
        self.width = width
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        text = tkinter.Text(self, relief="sunken", height=self.height, width=self.width)
        sbar.config(command=text.yview)
        text.config(yscrollcommand=sbar.set, font=font_setting)
        sbar.grid(row=0, column=1, sticky="nsew")
        text.grid(row=0, column=0, sticky="nsew")
        text.rowconfigure(0, weight=1)
        text.columnconfigure(0, weight=1)
        self.text = text
        
    def write(self, text):
        self.text.insert("end", str("\n"+text))
        self.text.see("end")
        self.text.update()
        
    def clear(self):
        self.text.delete("1.0", "end")
        self.text.update()

        
class MyLabel(tkinter.Label):
    def __init__(self, parent=None, **config):
        tkinter.Label.__init__(self, parent, **config)
        self.grid(sticky="nsew")
        self.config(bg="steel blue")
        self.config(font=font_setting)

class MyFrame(tkinter.Frame):
    def __init__(self, parent=None, **config):
        tkinter.Frame.__init__(self, parent, **config)
        self.grid(sticky="nsew", padx=pad_setting, pady=pad_setting)
        