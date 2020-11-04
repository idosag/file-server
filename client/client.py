import tkFileDialog
import tkMessageBox
import traceback
import subprocess
from Tkinter import *
import hashlib
import socket, os
CHUNK = 1024
root = Tk()
ICON = "drive.ico"
ERROR_ICON = "error.ico"
SAPARATE = "&~&~"
REQUEST = "00000008"
CODE = "00000000"
users = [""]
PORT = 8820
IP = "192.168.1.24"
msg = [""]
FTP_SAPARATE = "~&~"


def res(outputtext):
    width, height = root.maxsize()
    outputtext.height = height
    outputtext.width = width


def recv_by_chunk(my_socket):
    data = ""
    rcv = my_socket.recv(CHUNK)
    data += rcv
    while len(rcv) >= CHUNK:
        rcv = my_socket.recv(CHUNK)
        data += rcv
    return data


def show_error(self, *args):
    err = traceback.format_exception(*args)
    tkMessageBox.showerror('Exception',err)
# but this works too



def login_or_register_screen(my_socket):
     # create a GUI window
    global login_button
    global register_button
    global login_label
    root.geometry("600x300")  # set the configuration of GUI window
    root.title("Account Login")  # set the title of GUI window
    root.iconbitmap(ICON)

    # create a Form label
    login_label = Label(text="Choose Login Or Register", width="300", height="2", font=("Calibri", 13))
    login_label.pack()

    # create Login Button

    login_button = Button(text="Login", height="2", width="30", command=lambda: login(my_socket))
    login_button.pack()
    Label(text="").pack()

    # create a register button
    register_button = Button(text="Register", height="2", width="30", command=lambda: register(my_socket))
    register_button.pack()
    Tk.report_callback_exception = show_error
    root.mainloop()  # start the GUI

#-----------------------------------------------------------------register----------------------------------------------

def register(my_socket):
    global password
    global username
    global username_entry
    global password_entry



    global register_screen

    register_screen = Toplevel(root)
    register_screen.iconbitmap(ICON)
    register_screen.title("Register")
    register_screen.geometry("300x250")
    register_screen.grab_set()
    # Set text variables
    username = StringVar()
    password = StringVar()

    # Set label for user's instruction
    Label(register_screen, text="Please enter details below").pack()
    Label(register_screen, text="").pack()

    # Set username label
    username_lable = Label(register_screen, text="Username")
    username_lable.pack()

    # Set username entry
    # The Entry widget is a standard Tkinter widget used to enter or display a single line of text.

    username_entry = Entry(register_screen, textvariable=username)
    username_entry.pack()

    # Set password label
    password_lable = Label(register_screen, text="Password")
    password_lable.pack()

    # Set password entry
    password_entry = Entry(register_screen, textvariable=password, show='*')
    password_entry.pack()

    # Set register button
    Button(register_screen, text="Register", width=10, height=1, command=lambda: register_user(my_socket)).pack()


def register_user(my_socket):

# get username and password
    username_info = username.get()
    password_info = password.get()
    if password_info == "" or username_info == "":
        register_error_msg(my_socket, "you forgot to enter a user name or password")
    elif (r"%s\%s" % ("", "")) in username_info:
        register_error_msg(my_socket, "forbbiden char %s\%s" % ("", ""))
    else:
        my_socket.send(REQUEST + SAPARATE + CODE + SAPARATE + "sign_on")
        hash_password = hashlib.sha256(password_info.encode()).hexdigest()
        my_socket.send(REQUEST + SAPARATE + CODE + SAPARATE + username_info + FTP_SAPARATE + hash_password)

        username_entry.delete(0, END)
        password_entry.delete(0, END)
        data = recv_by_chunk(my_socket).split(SAPARATE)[2].split(FTP_SAPARATE)
        print data
        if data[0] != "success":
            register_error_msg(my_socket,data[0])
        else:
            Label(register_screen, text="Registration Success", fg="green", font=("calibri", 11)).pack()
            register_screen.destroy()


def register_error_msg(my_socket, error):
    global register_error_pop
    register_error_pop = Toplevel(register_screen)
    register_error_pop.title("error")
    register_error_pop.geometry("300x100")
    register_error_pop.protocol('WM_DELETE_WINDOW', delete_register_error)
    register_error_pop.iconbitmap(ERROR_ICON)
    Label(register_error_pop, text=error).pack()
    print 12
    Button(register_error_pop, text="OK", command=delete_register_error).pack()


def delete_register_error():
    register_error_pop.destroy()

#-----------------------------------------------------login------------------------------------------------------------

def login(my_socket):
    global login_screen
    global username_verify
    global password_verify
    global username_login_entry
    global password_login_entry
    login_screen = Toplevel(root)
    login_screen.iconbitmap(ICON)
    login_screen.title("Login")
    login_screen.geometry("300x250")
    Label(login_screen, text="Please enter details below to login").pack()
    Label(login_screen, text="").pack()
    login_screen.grab_set()



    username_verify = StringVar()
    password_verify = StringVar()

    Label(login_screen, text="Username").pack()
    username_login_entry = Entry(login_screen, textvariable=username_verify)
    username_login_entry.pack()
    Label(login_screen, text="").pack()
    Label(login_screen, text="Password").pack()
    password_login_entry = Entry(login_screen, textvariable=password_verify, show='*')
    password_login_entry.pack()
    Label(login_screen, text="").pack()
    Button(login_screen, text="Login", width=10, height=1, command=lambda: login_verify(my_socket)).pack()


def login_verify(my_socket):
#get username and password

    username = username_verify.get()
    password = password_verify.get()
    if password == "" or username == "":
        login_error_msg(my_socket,"you forgot to enter a user name or password")
    else:
        hash_password = hashlib.sha256(password.encode()).hexdigest()
        my_socket.send(REQUEST + SAPARATE + CODE + SAPARATE + "login")
        my_socket.send(REQUEST + SAPARATE + CODE + SAPARATE + username + FTP_SAPARATE + hash_password)

    # this will delete the entry after login button is pressed
        username_login_entry.delete(0, END)
        password_login_entry.delete(0, END)
        data = recv_by_chunk(my_socket).split(SAPARATE)[2].split(FTP_SAPARATE)
        print data[0]
        if data[0] != "success":
            login_error_msg(my_socket,data[0])
        else:
            users[0] = username
            msg[0] = data[1]
            login_sucess(my_socket)


def login_sucess(my_socket):

    global login_success_screen   # make login_success_screen global
    login_success_screen = Toplevel(login_screen)
    login_success_screen.grab_set()
    login_success_screen.protocol('WM_DELETE_WINDOW', lambda: delete_login_success(my_socket))
    login_success_screen.iconbitmap(ICON)
    login_success_screen.title("Success")
    login_success_screen.geometry("150x100")
    Label(login_success_screen, text="Login Success").pack()


# create OK button
    Button(login_success_screen, text="OK", command=lambda: delete_login_success(my_socket)).pack()


def delete_login_success(my_socket):
    login_success_screen.destroy()
    login_screen.destroy()
    login_button.destroy()
    register_button.destroy()
    login_label.destroy()
    main_system(my_socket)


def login_error_msg(my_socket, error):
    global error_pop
    error_pop = Toplevel(login_screen)
    error_pop.grab_set()
    error_pop.protocol('WM_DELETE_WINDOW', delete_password_not_recognised)
    error_pop.title("error")
    error_pop.geometry("300x100")
    error_pop.iconbitmap(ERROR_ICON)
    Label(error_pop, text=error).pack()
    Button(error_pop, text="OK", command=delete_password_not_recognised).pack()


def delete_password_not_recognised():
    error_pop.grab_release()
    login_screen.grab_set()
    error_pop.destroy()


#--------------------------------------------------to admin------------------------------------------------------------
def to_admin(my_socket):
    global admin_screen
    global username_to_promote_verify
    global username_to_promote_entry
    global username_to_promote
    my_socket.send(REQUEST + SAPARATE + CODE + SAPARATE + "to_admin")
    my_socket.send(REQUEST + SAPARATE + CODE + SAPARATE + users[0] + FTP_SAPARATE + users[0])
    data = recv_by_chunk(my_socket)
    print data
    if data.split(SAPARATE)[2] == "access denied":
        access_denied(my_socket)
    else:
        admin_screen = Toplevel(root)
        admin_screen.grab_set()
        admin_screen.iconbitmap(ICON)
        admin_screen.title("To Admin")
        admin_screen.geometry("300x250")
        Label(admin_screen, text="Please enter a user name to promote").pack()
        Label(admin_screen, text="").pack()
        username_to_promote_verify = StringVar()
        Label(admin_screen, text="Username").pack()
        username_to_promote_entry = Entry(admin_screen, textvariable=username_to_promote_verify)
        username_to_promote_entry.pack()
        Label(admin_screen, text="").pack()
        Button(admin_screen, text="OK", width=10, height=1, command=lambda: admin_verify(my_socket)).pack()


def admin_verify(my_socket):
    username_to_promote = username_to_promote_verify.get()
    if username_to_promote == "":
        admin_error_msg(my_socket, "you forgot to enter a user name")
    else:
        my_socket.send(REQUEST + SAPARATE + CODE + SAPARATE + "to_admin")
        my_socket.send(REQUEST + SAPARATE + CODE + SAPARATE + username_to_promote)

        # this will delete the entry after login button is pressed
        username_to_promote_entry.delete(0, END)
        data = recv_by_chunk(my_socket).split(SAPARATE)
        print data
        if data[2] != "success":
            admin_error_msg(my_socket, data[2])
        else:
            admin_sucess(my_socket)


def admin_sucess(my_socket):

    global admin_success_screen   # make login_success_screen global
    admin_success_screen = Toplevel(admin_screen)
    admin_success_screen.grab_set()
    admin_success_screen.iconbitmap(ICON)
    admin_success_screen.title("Success")
    admin_success_screen.geometry("150x100")
    admin_success_screen.protocol('WM_DELETE_WINDOW', lambda: delete_admin_success(my_socket))
    Label(admin_success_screen, text="Admin Success").pack()

# create OK button
    Button(admin_success_screen, text="OK", command=lambda: delete_admin_success(my_socket)).pack()


def delete_admin_success(my_socket):
    admin_success_screen.destroy()
    admin_screen.destroy()


def admin_error_msg(my_socket, error):
    global admin_pop
    admin_pop = Toplevel(admin_screen)
    admin_pop.grab_set()
    admin_pop.title("error")
    admin_pop.geometry("300x100")
    admin_pop.protocol('WM_DELETE_WINDOW', delete_admin_error)
    admin_pop.iconbitmap(ERROR_ICON)
    Label(admin_pop, text=error).pack()
    Button(admin_pop, text="OK", command=delete_admin_error).pack()


def delete_admin_error():
    admin_pop.destroy()
    admin_screen.grab_set()


def access_denied(my_socket):
    global access_pop
    access_pop = Toplevel(root)
    access_pop.grab_set()
    access_pop.title("error")
    access_pop.geometry("300x100")
    access_pop.iconbitmap(ERROR_ICON)
    Label(access_pop, text="access denied").pack()
    Button(access_pop, text="OK", command=delete_access_denied).pack()


def delete_access_denied():
    access_pop.destroy()


#----------------------------------------------------------save---------------------------------------------------------
def save(my_socket):
    root.filename = tkFileDialog.askopenfilename(initialdir="/", title="Select file")
    global save_screen
    global file_name_verify
    global file_name_entry
    global file_name
    global file_path
    global path_entry
    global path_verify
    file_path = root.filename
    if file_path != "":
        save_screen = Toplevel(root)
        save_screen.iconbitmap(ICON)
        save_screen.title("Save file")
        save_screen.geometry("300x250")
        save_screen.grab_set()
        Label(save_screen, text="Please enter a file name with type").pack()
        Label(save_screen, text="").pack()
        file_name_verify = StringVar()
        Label(save_screen, text="File name").pack()
        file_name_entry = Entry(save_screen, textvariable=file_name_verify)
        file_name_entry.pack()
        Label(save_screen, text="").pack()
        Button(save_screen, text="OK", width=10, height=1, command=lambda: save_verify(my_socket)).pack()


def save_verify(my_socket):
    file_name = file_name_verify.get()
    print os.path.getsize(file_path)
    if os.path.getsize(file_path) > 10000000:
        save_error_msg(my_socket, "file is to big")
    elif file_name == "" or file_path == "":
        save_error_msg(my_socket, "you forgot to enter a file name")
    elif not os.path.exists(file_path):
        save_error_msg(my_socket, "file path doesn't exist")
    else:
        with open(file_path, "rb") as read_file:
            file_data = read_file.read()
        print file_data
        my_socket.send(REQUEST + SAPARATE + CODE + SAPARATE + "save")
        my_socket.send(REQUEST + SAPARATE + CODE + SAPARATE + file_name.split(".")[0]
                       + FTP_SAPARATE + file_name.split(".")[1] + FTP_SAPARATE + file_data)

        # this will delete the entry after login button is pressed
        file_name_entry.delete(0, END)
        data = recv_by_chunk(my_socket).split(SAPARATE)
        print data
        if data[2] == "replace":
            replace_yes_no(my_socket)
            data = recv_by_chunk(my_socket).split(SAPARATE)
            print data
            if data[2] != "success" and data[2] != "canceled":
               save_error_msg(my_socket, data[2])
            elif data[2] == "canceled":
                cancel_msg(my_socket)
            else:
                save_sucess(my_socket)
        elif data[2] != "success":
            save_error_msg(my_socket, data[2])
        else:
            save_sucess(my_socket)


def save_sucess(my_socket):

    global save_success_screen   # make login_success_screen global
    save_success_screen = Toplevel(save_screen)
    save_success_screen.grab_set()
    save_success_screen.protocol('WM_DELETE_WINDOW', lambda: delete_save_success(my_socket))
    save_success_screen.iconbitmap(ICON)
    save_success_screen.title("Success")
    save_success_screen.geometry("150x100")
    Label(save_success_screen, text="Saved").pack()

# create OK button
    Button(save_success_screen, text="OK", command=lambda: delete_save_success(my_socket)).pack()


def delete_save_success(my_socket):
    save_success_screen.destroy()
    save_screen.destroy()


def save_error_msg(my_socket, error):
    global save_pop
    save_pop = Toplevel(save_screen)
    save_pop.grab_set()
    save_pop.title("error")
    save_pop.geometry("300x100")
    save_pop.protocol('WM_DELETE_WINDOW', lambda: delete_save_error(error))
    save_pop.iconbitmap(ERROR_ICON)
    Label(save_pop, text=error).pack()
    Button(save_pop, text="OK", command=lambda: delete_save_error(error)).pack()


def cancel_msg(my_socket):
    global cancel_pop
    cancel_pop = Toplevel(save_screen)
    cancel_pop.grab_set()
    cancel_pop.title("error")
    cancel_pop.geometry("300x100")
    cancel_pop.protocol('WM_DELETE_WINDOW', delete_cancel)
    cancel_pop.iconbitmap(ERROR_ICON)
    Label(cancel_pop, text="canceled").pack()
    Button(cancel_pop, text="OK", command=delete_cancel).pack()


def delete_cancel():
    cancel_pop.destroy()
    save_screen.grab_set()


def delete_save_error(error):
    if error == "file is to big":
        save_pop.destroy()
        save_screen.destroy()
    else:
        save_pop.destroy()
        save_screen.grab_set()


def replace_yes_no(my_socket):
    ques = tkMessageBox.askquestion('replace', 'there is a file with this name do you want to replace him?')
    if ques == 'yes':
        my_socket.send(REQUEST + SAPARATE + CODE + SAPARATE + "replace")
    else:
        my_socket.send(REQUEST + SAPARATE + CODE + SAPARATE + "cancel")


#-------------------------------------------------------share----------------------------------------------------
def share(my_socket):
    global share_screen
    global file_name_verify
    global file_name_entry
    global file_name
    global user_to_share
    global user_to_share_entry
    global user_to_share_verify
    share_screen = Toplevel(root)
    share_screen.grab_set()
    share_screen.iconbitmap(ICON)
    share_screen.title("Share file")
    share_screen.geometry("300x250")
    Label(share_screen, text="Please enter a file name with type").pack()
    Label(share_screen, text="").pack()
    file_name_verify = StringVar()
    user_to_share_verify = StringVar()
    Label(share_screen, text="File name").pack()
    file_name_entry = Entry(share_screen, textvariable=file_name_verify)
    file_name_entry.pack()
    Label(share_screen, text="").pack()
    Label(share_screen, text="User to share").pack()
    user_to_share_entry = Entry(share_screen, textvariable=user_to_share_verify)
    user_to_share_entry.pack()
    Label(share_screen, text="").pack()
    Button(share_screen, text="OK", width=10, height=1, command=lambda: share_verify(my_socket)).pack()


def share_verify(my_socket):
    file_name = file_name_verify.get()
    user_to_share = user_to_share_verify.get()
    if file_name == "" or user_to_share == "":
        share_error_msg(my_socket, "you forgot to enter a file name or user")
    else:
        my_socket.send(REQUEST + SAPARATE + CODE + SAPARATE + "share")
        my_socket.send(REQUEST + SAPARATE + CODE + SAPARATE + user_to_share + FTP_SAPARATE + file_name)

        # this will delete the entry after login button is pressed
        file_name_entry.delete(0, END)
        user_to_share_entry.delete(0, END)
        data = recv_by_chunk(my_socket).split(SAPARATE)
        print data
        if data[2] != "success":
            share_error_msg(my_socket, data[2])
        else:
            share_sucess(my_socket)


def share_sucess(my_socket):

    global share_success_screen   # make login_success_screen global
    share_success_screen = Toplevel(share_screen)
    share_success_screen.grab_set()
    share_success_screen.iconbitmap(ICON)
    share_success_screen.title("Success")
    share_success_screen.geometry("150x100")
    share_success_screen.protocol('WM_DELETE_WINDOW', lambda: delete_share_success(my_socket))
    Label(share_success_screen, text="Shared").pack()

# create OK button
    Button(share_success_screen, text="OK", command=lambda: delete_share_success(my_socket)).pack()


def delete_share_success(my_socket):
    share_success_screen.destroy()
    share_screen.destroy()


def share_error_msg(my_socket, error):
    global share_pop
    share_pop = Toplevel(share_screen)
    share_pop.grab_set()
    share_pop.title("error")
    share_pop.geometry("300x100")
    share_pop.protocol('WM_DELETE_WINDOW', lambda: delete_share_error(error))
    share_pop.iconbitmap(ERROR_ICON)
    Label(share_pop, text=error).pack()
    Button(share_pop, text="OK", command=lambda: delete_share_error(error)).pack()


def delete_share_error(error):
    share_pop.destroy()
    share_screen.grab_set()


#---------------------------------------------------download---------------------------------------------------


def download(my_socket):
    global download_screen
    global file_path_verify
    global file_path_entry
    global file_path
    download_screen = Toplevel(root)
    download_screen.grab_set()
    download_screen.iconbitmap(ICON)
    download_screen.title("download")
    download_screen.geometry("300x250")
    Label(download_screen, text="Please enter a file path").pack()
    Label(download_screen, text="").pack()
    file_path_verify = StringVar()
    Label(download_screen, text="File path").pack()
    file_path_entry = Entry(download_screen, textvariable=file_path_verify)
    file_path_entry.pack()
    Label(download_screen, text="").pack()
    Button(download_screen, text="OK", width=10, height=1, command=lambda: download_verify(my_socket)).pack()


def download_verify(my_socket):
    file_path = file_path_verify.get()
    if file_path == "":
        download_error_msg(my_socket, "you forgot to enter a file path")
    else:
        my_socket.send(REQUEST + SAPARATE + CODE + SAPARATE + "download")
        my_socket.send(REQUEST + SAPARATE + CODE + SAPARATE + file_path)

        # this will delete the entry after login button is pressed
        file_path_entry.delete(0, END)
        data = recv_by_chunk(my_socket).split(SAPARATE)[2].split(FTP_SAPARATE)
        print data
        if data[0] != "success":
            download_error_msg(my_socket, data[0])
        else:
            if len(file_path.split(r"%s\%s" % ("", ""))) > 1:
                with open(r"C:\Users\User\Downloads\%s" % (file_path.split(r"%s\%s" % ("", ""))[1]), "wb") as write_file:
                    write_file.write(data[3])
                os.startfile(r'C:\Users\User\Downloads\%s' % (file_path.split(r"%s\%s" % ("", ""))[1]))
            else:
                with open(r"C:\Users\User\Downloads\%s" % (file_path), "wb") as write_file:
                    write_file.write(data[3])
                os.startfile(r'C:\Users\User\Downloads\%s' % (file_path))
            download_sucess(my_socket)


def download_sucess(my_socket):

    global download_success_screen   # make login_success_screen global
    download_success_screen = Toplevel(download_screen)
    download_success_screen.iconbitmap(ICON)
    download_success_screen.grab_set()
    download_success_screen.title("Success")
    download_success_screen.geometry("150x100")
    download_success_screen.protocol('WM_DELETE_WINDOW', lambda: delete_download_success(my_socket))
    Label(download_success_screen, text="Download Success").pack()

# create OK button
    Button(download_success_screen, text="OK", command=lambda: delete_download_success(my_socket)).pack()


def delete_download_success(my_socket):
    download_success_screen.destroy()
    download_screen.destroy()


def download_error_msg(my_socket, error):
    global download_pop
    download_pop = Toplevel(download_screen)
    download_pop.grab_set()
    download_pop.title("error")
    download_pop.geometry("300x100")
    download_pop.protocol('WM_DELETE_WINDOW', delete_download_error)
    download_pop.iconbitmap(ERROR_ICON)
    Label(download_pop, text=error).pack()
    Button(download_pop, text="OK", command=delete_download_error).pack()


def delete_download_error():
    download_pop.destroy()
    download_screen.grab_set()


#-------------------------------------------------------switch user---------------------------------------------------
def switch(my_socket, txt):
    global switch_screen
    global username_verify
    global password_verify
    global username_switch_entry
    global password_switch_entry
    switch_screen = Toplevel(root)
    switch_screen.grab_set()
    switch_screen.iconbitmap(ICON)
    switch_screen.title("Switch user")
    switch_screen.geometry("300x250")
    Label(switch_screen, text="Please enter details below to login").pack()
    Label(switch_screen, text="").pack()



    username_verify = StringVar()
    password_verify = StringVar()

    Label(switch_screen, text="Username").pack()
    username_switch_entry = Entry(switch_screen, textvariable=username_verify)
    username_switch_entry.pack()
    Label(switch_screen, text="").pack()
    Label(switch_screen, text="Password").pack()
    password_switch_entry = Entry(switch_screen, textvariable=password_verify, show='*')
    password_switch_entry.pack()
    Label(switch_screen, text="").pack()
    Button(switch_screen, text="Login", width=10, height=1, command=lambda: switch_verify(my_socket, txt)).pack()


def switch_verify(my_socket, txt):
#get username and password

    username = username_verify.get()
    password = password_verify.get()
    if password == "" or username == "":
        switch_error_msg(my_socket,"you forgot to enter a user name or password")
    else:
        hash_password = hashlib.sha256(password.encode()).hexdigest()
        my_socket.send(REQUEST + SAPARATE + CODE + SAPARATE + "switch")
        my_socket.send(REQUEST + SAPARATE + CODE + SAPARATE + username + FTP_SAPARATE + hash_password)

    # this will delete the entry after login button is pressed
        username_switch_entry.delete(0, END)
        password_switch_entry.delete(0, END)
        data = recv_by_chunk(my_socket).split(SAPARATE)[2].split(FTP_SAPARATE)
        print data
        if data[0] != "success":
            switch_error_msg(my_socket,data[0])
        else:
            txt.config(state=NORMAL)
            msg[0] = data[1]
            print data[1]
            print msg[0]
            root.title("hello " + username)
            width, height = root.maxsize()
            txt.delete('1.0',END)
            txt.insert(INSERT, "you're new messages are:\n" + msg[0])
            txt.config(state=DISABLED)
            users[0] = username

            switch_sucess(my_socket)


def switch_sucess(my_socket):

    global switch_success_screen   # make login_success_screen global
    switch_success_screen = Toplevel(switch_screen)
    switch_success_screen.grab_set()
    switch_success_screen.iconbitmap(ICON)
    switch_success_screen.title("Success")
    switch_success_screen.geometry("150x100")
    Label(switch_success_screen, text="Switched").pack()
    switch_success_screen.protocol('WM_DELETE_WINDOW', lambda: delete_switch_success(my_socket))
# create OK button
    Button(switch_success_screen, text="OK", command=lambda: delete_switch_success(my_socket)).pack()


def delete_switch_success(my_socket):
    switch_success_screen.destroy()
    switch_screen.destroy()


def switch_error_msg(my_socket, error):
    global switch_pop
    switch_pop = Toplevel(switch_screen)
    switch_pop.grab_set()
    switch_pop.title("error")
    switch_pop.geometry("300x100")
    switch_pop.protocol('WM_DELETE_WINDOW', delete_switch_password_not_recognised)
    switch_pop.iconbitmap(ERROR_ICON)
    Label(switch_pop, text=error).pack()
    Button(switch_pop, text="OK", command=delete_switch_password_not_recognised).pack()


def delete_switch_password_not_recognised():
    switch_pop.destroy()
    switch_screen.grab_set()


#----------------------------------------------------------rename-----------------------------------------------------
def rename(my_socket):
    global rename_screen
    global file_name_verify
    global new_file_name_verify
    global file_name_entry
    global new_file_name_entry
    rename_screen = Toplevel(root)
    rename_screen.grab_set()
    rename_screen.iconbitmap(ICON)
    rename_screen.title("rename file")
    rename_screen.geometry("300x250")
    Label(rename_screen, text="Please enter details below").pack()
    Label(rename_screen, text="").pack()



    file_name_verify = StringVar()
    new_file_name_verify = StringVar()

    Label(rename_screen, text="File to rename").pack()
    file_name_entry = Entry(rename_screen, textvariable=file_name_verify)
    file_name_entry.pack()
    Label(rename_screen, text="").pack()
    Label(rename_screen, text="New file name").pack()
    new_file_name_entry = Entry(rename_screen, textvariable=new_file_name_verify)
    new_file_name_entry.pack()
    Label(rename_screen, text="").pack()
    Button(rename_screen, text="OK", width=10, height=1, command=lambda: rename_verify(my_socket)).pack()


def rename_verify(my_socket):
#get username and password

    file_name = file_name_verify.get()
    new_file_name = new_file_name_verify.get()
    if file_name == "" or new_file_name == "":
        rename_error_msg(my_socket,"you forgot to enter a new file name or file to rename")
    elif file_name == new_file_name:
        rename_error_msg(my_socket, "this is the same name")
    else:
        my_socket.send(REQUEST + SAPARATE + CODE + SAPARATE + "rename")
        my_socket.send(REQUEST + SAPARATE + CODE + SAPARATE + file_name + FTP_SAPARATE + new_file_name)

    # this will delete the entry after login button is pressed
        file_name_entry.delete(0, END)
        new_file_name_entry.delete(0, END)
        data = recv_by_chunk(my_socket).split(SAPARATE)
        print data
        if data[2] != "success":
            rename_error_msg(my_socket,data[2])
        else:
            rename_sucess(my_socket)


def rename_sucess(my_socket):

    global rename_success_screen   # make login_success_screen global
    rename_success_screen = Toplevel(rename_screen)
    rename_success_screen.grab_set()
    rename_success_screen.iconbitmap(ICON)
    rename_success_screen.title("Success")
    rename_success_screen.geometry("150x100")
    rename_success_screen.protocol('WM_DELETE_WINDOW', lambda: delete_rename_success(my_socket))
    Label(rename_success_screen, text="renamed").pack()

# create OK button
    Button(rename_success_screen, text="OK", command=lambda: delete_rename_success(my_socket)).pack()


def delete_rename_success(my_socket):
    rename_success_screen.destroy()
    rename_screen.destroy()


def rename_error_msg(my_socket, error):
    global rename_pop
    rename_pop = Toplevel(rename_screen)
    rename_pop.grab_set()
    rename_pop.title("error")
    rename_pop.geometry("300x100")
    rename_pop.protocol('WM_DELETE_WINDOW', delete_rename_error)
    rename_pop.iconbitmap(ERROR_ICON)
    Label(rename_pop, text=error).pack()
    Button(rename_pop, text="OK", command=delete_rename_error).pack()


def delete_rename_error():
    rename_pop.destroy()
    rename_screen.grab_set()


#------------------------------------------------------delete file----------------------------------------------------
def delete(my_socket):
    global delete_screen
    global file_name_verify
    global file_name_entry
    global file_name
    delete_screen = Toplevel(root)
    delete_screen.grab_set()
    delete_screen.iconbitmap(ICON)
    delete_screen.title("delete file")
    delete_screen.geometry("300x250")
    Label(delete_screen, text="Please enter a file name").pack()
    Label(delete_screen, text="").pack()
    file_name_verify = StringVar()
    Label(delete_screen, text="File name").pack()
    file_name_entry = Entry(delete_screen, textvariable=file_name_verify)
    file_name_entry.pack()
    Label(delete_screen, text="").pack()
    Button(delete_screen, text="OK", width=10, height=1, command=lambda: delete_verify(my_socket)).pack()


def delete_verify(my_socket):
    file_name = file_name_verify.get()
    if file_name == "":
        delete_error_msg(my_socket, "you forgot to enter a file name")
    else:
        my_socket.send(REQUEST + SAPARATE + CODE + SAPARATE + "delete")
        my_socket.send(REQUEST + SAPARATE + CODE + SAPARATE + file_name)

        # this will delete the entry after login button is pressed
        file_name_entry.delete(0, END)
        data = recv_by_chunk(my_socket).split(SAPARATE)[2].split(FTP_SAPARATE)
        print data
        if data[0] != "success":
            delete_error_msg(my_socket, data[0])
        else:
            delete_sucess(my_socket)


def delete_sucess(my_socket):
    global delete_success_screen   # make login_success_screen global
    delete_success_screen = Toplevel(delete_screen)
    delete_success_screen.grab_set()
    delete_success_screen.iconbitmap(ICON)
    delete_success_screen.title("Success")
    delete_success_screen.geometry("150x100")
    delete_success_screen.protocol('WM_DELETE_WINDOW', lambda: delete_delete_success(my_socket))
    Label(delete_success_screen, text="Deleted").pack()

# create OK button
    Button(delete_success_screen, text="OK", command=lambda: delete_delete_success(my_socket)).pack()


def delete_delete_success(my_socket):
    delete_success_screen.destroy()
    delete_screen.destroy()


def delete_error_msg(my_socket, error):
    global delete_pop
    delete_pop = Toplevel(delete_screen)
    delete_pop.grab_set()
    delete_pop.title("error")
    delete_pop.geometry("300x100")
    delete_pop.protocol('WM_DELETE_WINDOW', delete_delete_error)
    delete_pop.iconbitmap(ERROR_ICON)
    Label(delete_pop, text=error).pack()
    Button(delete_pop, text="OK", command=delete_delete_error).pack()



def delete_delete_error():
    delete_pop.destroy()
    delete_screen.grab_set()


def main_system(my_socket):
    root.title("hello " + users[0])
    root.iconbitmap("drive.ico")

    menubar = Menu(root)
    exitmenu = Menu(menubar, tearoff=0)
    width, height = root.maxsize()
    outputtext = Text(root, background="white", width=width, height=height)
    outputtext.insert(INSERT, "you're new messages are:\n" + msg[0])
    outputtext.config(state=DISABLED)
    outputtext.pack()
    # filemenu.add_separator()
    exitmenu.add_command(label="press to exit", command=root.quit)
    menubar.add_cascade(label="Exit", menu=exitmenu)

    switchmenu = Menu(menubar, tearoff=0)
    # filemenu.add_separator()
    switchmenu.add_command(label="press to switch users", command=lambda: switch(my_socket, outputtext))
    menubar.add_cascade(label="Switch user", menu=switchmenu)

    savemenu = Menu(menubar, tearoff=0)
    savemenu.add_command(label="press to save file", command=lambda: save(my_socket))

    menubar.add_cascade(label="Save", menu=savemenu)
    sharemenu = Menu(menubar, tearoff=0)
    sharemenu.add_command(label="press to share file", command=lambda: share(my_socket))
    menubar.add_cascade(label="Share", menu=sharemenu)

    downloadmenu = Menu(menubar, tearoff=0)
    downloadmenu.add_command(label="press to download file", command=lambda: download(my_socket))
    menubar.add_cascade(label="Download", menu=downloadmenu)

    renamemenu = Menu(menubar, tearoff=0)
    renamemenu.add_command(label="press to rename file", command=lambda: rename(my_socket))
    menubar.add_cascade(label="Rename", menu=renamemenu)

    deletemenu = Menu(menubar, tearoff=0)
    deletemenu.add_command(label="press to delete file", command=lambda: delete(my_socket))
    menubar.add_cascade(label="Delete file", menu=deletemenu)

    to_adminmenu = Menu(menubar, tearoff=0)
    to_adminmenu.add_command(label="press to promote user to administrator", command=lambda: to_admin(my_socket))
    menubar.add_cascade(label="To_admin", menu=to_adminmenu)

    root.config(menu=menubar)


def main():
    try:
        my_socket = socket.socket()
        my_socket.connect((IP, PORT))
        login_or_register_screen(my_socket)
        my_socket.send(REQUEST + SAPARATE + CODE + SAPARATE + "exit")
        my_socket.send(REQUEST + SAPARATE + CODE + SAPARATE + users[0])
        my_socket.close()
    except Exception as e:
        print(e)
        my_socket.close()

if __name__ == "__main__":
    main()