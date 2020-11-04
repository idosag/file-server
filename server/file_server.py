import socket, os, sys, json, threading
from threading import Thread
CHUNK = 1024
SAPARATE = "&~&~"
FTP_SAPARATE = "~&~"
REPLY = "00000000"
current_user = [""]
IP = "0.0.0.0"
PORT = 8820
CODE = "00000000"
QUEUE_SIZE = 5
l1 = threading.Lock()


def recv_by_chunk(client_socket):
    data = ""
    rcv = client_socket.recv(CHUNK)
    data += rcv
    while len(rcv) >= CHUNK:
        rcv = client_socket.recv(CHUNK)
        data += rcv
    return data


def log_in(user_name, password, client_socket):
    with open("users.json", "r") as users:
        data = json.load(users)
    if user_name in data:
        if data[user_name]["password"] == password:
            if data[user_name]["state"] == "offline":
                to_send = ""
                for i in data[user_name]["messages"]:
                    to_send += i + "\n"
                data[user_name]["messages"] = []
                client_socket.send(REPLY + SAPARATE + CODE + SAPARATE + "success" + FTP_SAPARATE + to_send)
                current_user[0] = user_name
                data[user_name]["state"] = "online"
                with open("users.json", "w") as json_write:
                    json_write.write(json.dumps(data, json_write))
                return True, user_name
            else:
                client_socket.send(REPLY + SAPARATE + CODE + SAPARATE + "you are connected from other device")
                return False, user_name
    else:
        client_socket.send(REPLY + SAPARATE + CODE + SAPARATE + "wrong user name or password")
    return False,user_name


def save(user_name, file_name, data, client_socket):
    with open("users.json", "r") as users:
        js_data = json.load(users)
    if not os.path.exists(user_name):
        os.makedirs(user_name)
    if file_name in js_data[user_name]["files"]:
        client_socket.send(REPLY + SAPARATE + CODE + SAPARATE + "replace")
        rcv_data = recv_by_chunk(client_socket).split(SAPARATE)
        if rcv_data[2] == "replace":
            with open(r"%s\%s" % (user_name, file_name), "wb") as write_file:
                write_file.write(data)
            js_data[user_name]["files"][file_name] = "open"
            with open("users.json", "w") as json_write:
                json_write.write(json.dumps(js_data, json_write))
            client_socket.send(REPLY + SAPARATE + CODE + SAPARATE + "success")
        else:
            client_socket.send(REPLY + SAPARATE + CODE + SAPARATE + "canceled")
    elif file_name in js_data[user_name]["shared_files"]:
        if len(file_name.split(r"%s\%s" % ("", ""))) > 1:
            if js_data[user_name]["shared_files"][file_name] == "open" or js_data[user_name]["shared_files"][file_name] == "working":
                client_socket.send(REPLY + SAPARATE + CODE + SAPARATE + "replace")
                rcv_data = recv_by_chunk(client_socket).split(SAPARATE)
                if rcv_data[2] == "replace":
                    with open(file_name, "wb") as write_file:
                        write_file.write(data)
                    js_data[user_name]["shared_files"][file_name] = "open"
                    for i in js_data:
                        if i != user_name and file_name in js_data[i]["shared_files"]:
                            js_data[i]["shared_files"][file_name] = "open"
                        elif i != user_name and file_name.split(r"%s\%s" % ("", ""))[1] in js_data[i]["shared_files"]:
                            js_data[i]["shared_files"][file_name.split(r"%s\%s" % ("", ""))[1]] = "open"
                    with open("users.json", "w") as json_write:
                        json_write.write(json.dumps(js_data, json_write))
                    client_socket.send(REPLY + SAPARATE + CODE + SAPARATE + "success")
                else:
                    client_socket.send(REPLY + SAPARATE + CODE + SAPARATE + "canceled")
            else:
                client_socket.send(REPLY + SAPARATE + CODE + SAPARATE + "someone else is working on the file")
        else:
            if js_data[user_name]["shared_files"][file_name] == "open" or js_data[user_name]["shared_files"][file_name] == "working":
                client_socket.send(REPLY + SAPARATE + CODE + SAPARATE + "replace")
                rcv_data = recv_by_chunk(client_socket).split(SAPARATE)
                if rcv_data[2] == "replace":
                    print("33456")
                    with open(r"%s\%s" % (user_name, file_name), "wb") as write_file:
                        write_file.write(data)
                    print("33456")
                    js_data[user_name]["shared_files"][file_name] = "open"
                    for i in js_data:
                        if i != user_name and file_name in js_data[i]["shared_files"]:
                            js_data[i]["shared_files"][file_name] = "open"
                        elif i != user_name and r"%s\%s" % (user_name, file_name) in js_data[i]["shared_files"]:
                            js_data[i]["shared_files"][r"%s\%s" % (user_name, file_name)] = "open"
                    with open("users.json", "w") as json_write:
                        json_write.write(json.dumps(js_data, json_write))
                    client_socket.send(REPLY + SAPARATE + CODE + SAPARATE + "success")
                else:
                    client_socket.send(REPLY + SAPARATE + CODE + SAPARATE + "canceled")
            else:
                client_socket.send(REPLY + SAPARATE + CODE + SAPARATE + "someone else is working on the file")
    else:
        with open(r"%s\%s" % (user_name, file_name), "wb") as write_file:
            write_file.write(data)
        js_data[user_name]["files"][file_name] = "open"
        with open("users.json", "w") as json_write:
            json_write.write(json.dumps(js_data, json_write))
        client_socket.send(REPLY + SAPARATE + CODE + SAPARATE + "success")


def log_on(user_name, password, client_socket):
    with open("users.txt", "a") as users:
        cnt = 0
        if not user_exist(user_name):
            print 1234
            with open("users.json", "r") as json_read:
                js_dic = json.load(json_read)
            print 45
            js_dic[user_name] = {"password": password, "permission": "user", "files": {}, "shared_files": {}, "messages": [], "state": "offline"}
            with open("users.json", "w") as json_write:
                json_write.write(json.dumps(js_dic, json_write))
            client_socket.send(REPLY + SAPARATE + CODE + SAPARATE + "success")
            return True, user_name, password
        client_socket.send(REPLY + SAPARATE + CODE + SAPARATE + "sorry there is a user with that name try another name")
        return False, user_name, password


def user_exist(user_name):
    with open("users.json", "r") as users:
        data = json.load(users)
        return user_name in data


def to_admin(user_name, user_to_promote, client_socket):
    with open("users.json", "r") as users:
        data = json.load(users)
    if user_name == user_to_promote:
        print data[user_name]["permission"]
        if data[user_name]["permission"] != "administrator":
            print 567
            client_socket.send(REPLY + SAPARATE + CODE + SAPARATE + "access denied")
        else:
            client_socket.send(REPLY + SAPARATE + CODE + SAPARATE + "success")
    else:
        if user_name in data and data[user_name]["permission"] == "administrator":
            if user_exist(user_to_promote):
                data[user_to_promote]["permission"] = "administrator"
                with open("users.json", "w") as json_write:
                    json_write.write(json.dumps(data, json_write))
                client_socket.send(REPLY + SAPARATE + CODE + SAPARATE + "success")
            else:
                client_socket.send(REPLY + SAPARATE + CODE + SAPARATE + "user not found")
        else:
            client_socket.send(REPLY + SAPARATE + CODE + SAPARATE + "access denied")


def share(user_name, user_to_share, file_name, client_socket):
    with open("users.json", "r") as users:
        data = json.load(users)
    if user_to_share in data:
        if file_name in data[user_name]["files"]:
            print 78
            data[user_name]["shared_files"][file_name] = "open"
            del data[user_name]["files"][file_name]
            data[user_to_share]["shared_files"][r"%s\%s" % (user_name, file_name)] = "open"
            data[user_to_share]["messages"].append("%s share with you a file %s" % (user_name, r"%s\%s" % (user_name, file_name)))
            with open("users.json", "w") as json_write:
                json_write.write(json.dumps(data, json_write))
            client_socket.send(REPLY + SAPARATE + CODE + SAPARATE + "success")
        elif file_name in data[user_name]["shared_files"]:
            print 78
            if r"%s\%s" % (user_name, file_name) not in data[user_to_share]["shared_files"] and len(file_name.split(r"%s\%s" % ("", ""))) == 1:
                print 34
                if data[user_name]["shared_files"][file_name] == "working":
                    data[user_to_share]["shared_files"][r"%s\%s" % (user_name, file_name)] = "blocked"
                else:
                    data[user_to_share]["shared_files"][r"%s\%s" % (user_name, file_name)] = data[user_name]["shared_files"][file_name]
                data[user_to_share]["messages"].append("%s share with you a file %s" % (user_name, r"%s\%s" % (user_name, file_name)))
                with open("users.json", "w") as json_write:
                    json_write.write(json.dumps(data, json_write))
                client_socket.send(REPLY + SAPARATE + CODE + SAPARATE + "success")

            elif len(file_name.split(r"%s\%s" % ("", ""))) > 1:
                print 23
                if file_name.split(r"%s\%s" % ("", ""))[1] not in data[user_to_share]["shared_files"] and file_name not in data[user_to_share]["shared_files"]:
                    if data[user_name]["shared_files"][file_name] == "working":
                        data[user_to_share]["shared_files"][file_name] = "blocked"
                    else:
                        data[user_to_share]["shared_files"][file_name] = \
                        data[user_name]["shared_files"][file_name]
                    data[user_to_share]["messages"].append("%s share with you a file %s" % (user_name, file_name))
                    with open("users.json", "w") as json_write:
                        json_write.write(json.dumps(data, json_write))
                    client_socket.send(REPLY + SAPARATE + CODE + SAPARATE + "success")

                else:
                    client_socket.send(REPLY + SAPARATE + CODE + SAPARATE + "file is already shared")
            else:
                print 23
                client_socket.send(REPLY + SAPARATE + CODE + SAPARATE + "file is already shared")
        else:
            client_socket.send(REPLY + SAPARATE + CODE + SAPARATE + "file doesn't exist")
    else:
        client_socket.send(REPLY + SAPARATE + CODE + SAPARATE + "wrong user name")


def download(user_name, file_path, client_socket):
    with open("users.json", "r") as users:
        js_data = json.load(users)
    if file_path in js_data[user_name]["files"]:
        with open(r"%s\%s" % (user_name, file_path), "rb") as read_file:
            data = read_file.read()
        client_socket.send(REPLY + SAPARATE + CODE + SAPARATE + "success" + FTP_SAPARATE + file_path.split(".")[0]
                           + FTP_SAPARATE + file_path.split(".")[1] + FTP_SAPARATE + data)
    elif file_path in js_data[user_name]["shared_files"]:
        if len(file_path.split(r"%s\%s" % ("", ""))) > 1:
            with open(file_path, "rb") as read_file:
                data = read_file.read()
            client_socket.send(REPLY + SAPARATE + CODE + SAPARATE + "success" + FTP_SAPARATE +
                               file_path.split(r"%s\%s" % ("", ""))[1].split(".")[0] + FTP_SAPARATE +
                               file_path.split(r"%s\%s" % ("", ""))[1].split(".")[1] + FTP_SAPARATE + data)
            print 78
            if js_data[user_name]["shared_files"][file_path] == "open":
                for i in js_data:
                    if i != user_name and file_path in js_data[i]["shared_files"]:
                        js_data[i]["shared_files"][file_path] = "blocked"
                    elif i != user_name and file_path.split(r"%s\%s" % ("", ""))[1] in js_data[i]["shared_files"]:
                        js_data[i]["shared_files"][file_path.split(r"%s\%s" % ("", ""))[1]] = "blocked"
                    elif i == user_name:
                        js_data[user_name]["shared_files"][file_path] = "working"
                with open("users.json", "w") as json_write:
                    json_write.write(json.dumps(js_data, json_write))
                print 23
        else:
            with open(r"%s\%s" % (user_name, file_path), "rb") as read_file:
                data = read_file.read()
            client_socket.send(REPLY + SAPARATE + CODE + SAPARATE + "success" + FTP_SAPARATE +
                               file_path.split(".")[0] + FTP_SAPARATE + file_path.split(".")[
                                   1] + FTP_SAPARATE + data)
            if js_data[user_name]["shared_files"][file_path] == "open":
                for i in js_data:
                    if i != user_name and (r"%s\%s" % (user_name, file_path) in js_data[i]["shared_files"]):
                        js_data[i]["shared_files"][r"%s\%s" % (user_name, file_path)] = "blocked"
                    elif i == user_name:
                        js_data[user_name]["shared_files"][file_path] = "working"
                with open("users.json", "w") as json_write:
                    json_write.write(json.dumps(js_data, json_write))
    else:
        client_socket.send(REPLY + SAPARATE + CODE + SAPARATE + "file doesn't exist")


def switch(online_user, user_name, password, client_socket):
    print 345
    with open("users.json", "r") as users:
        data = json.load(users)
    if user_exist(user_name):
        if data[user_name]["password"] == password:
            if data[user_name]["state"] == "offline":
                print 22
                data[online_user]["state"] = "offline"
                for i in data[online_user]["shared_files"]:
                    if data[online_user]["shared_files"][i] == "working":
                        if len(i.split(r"%s\%s" % ("", ""))) > 1:
                            for j in data:
                                if i != online_user and i in data[j]["shared_files"]:
                                    data[j]["shared_files"][i] = "open"
                                elif i != online_user and i.split(r"%s\%s" % ("", ""))[1] in data[j]["shared_files"]:
                                    data[j]["shared_files"][i.split(r"%s\%s" % ("", ""))[1]] = "open"
                                elif i == online_user:
                                    data[online_user]["shared_files"][i] = "open"
                        else:
                            for j in data:
                                if i != online_user and i in data[j]["shared_files"]:
                                    data[j]["shared_files"][i] = "open"
                                elif i != online_user and (r"%s\%s" % (online_user, i)) in data[j]["shared_files"]:
                                    data[j]["shared_files"][(r"%s\%s" % (online_user, i))] = "open"
                                elif i == online_user:
                                    data[online_user]["shared_files"][i] = "open"
                to_send = ""
                for i in data[user_name]["messages"]:
                    to_send += i + "\n"
                data[user_name]["messages"] = []
                client_socket.send(REPLY + SAPARATE + CODE + SAPARATE + "success" + FTP_SAPARATE + to_send)
                data[user_name]["state"] = "online"
                current_user[0] = user_name
                with open("users.json", "w") as json_write:
                    json_write.write(json.dumps(data, json_write))
                return True, user_name
            else:
                client_socket.send(REPLY + SAPARATE + CODE + SAPARATE + "you are connected from other device")
                return False, user_name
        client_socket.send(REPLY + SAPARATE + CODE + SAPARATE + "wrong user name or password")
    else:
        client_socket.send(REPLY + SAPARATE + CODE + SAPARATE + "wrong user name or password")
    return False,user_name


def rename(user_name, file_name, new_file_name, client_socket):
    with open("users.json", "r") as users:
        data = json.load(users)
    if file_name in data[user_name]["files"]:
        os.rename(r"%s\%s" % (user_name, file_name), r"%s\%s" % (user_name, new_file_name))
        print file_name
        data[user_name]["files"][new_file_name] = data[user_name]["files"][file_name]
        print 45
        del data[user_name]["files"][file_name]
        with open("users.json", "w") as json_write:
            json_write.write(json.dumps(data, json_write))
        client_socket.send(REPLY + SAPARATE + CODE + SAPARATE + "success")
    elif file_name in data[user_name]["shared_files"]:
        if data[user_name]["shared_files"][file_name] == "working" or data[user_name]["shared_files"][file_name] == "open":
            if len(file_name.split(r"%s\%s" % ("", ""))) > 1:
                os.rename(file_name, r"%s\%s" % (file_name.split(r"%s\%s" % ("", ""))[0], new_file_name))
                for i in data:
                    if file_name in data[i]["shared_files"]:
                        data[i]["shared_files"][r"%s\%s" % (file_name.split(r"%s\%s" % ("", ""))[0], new_file_name)] = data[i]["shared_files"][file_name]
                        del data[i]["shared_files"][file_name]
                    elif file_name.split(r"%s\%s" % ("", ""))[1] in data[i]["shared_files"]:
                        data[i]["shared_files"][new_file_name] = data[i]["shared_files"][file_name.split(r"%s\%s" % ("", ""))[1]]
                        del data[i]["shared_files"][file_name.split(r"%s\%s" % ("", ""))[1]]
                with open("users.json", "w") as json_write:
                    json_write.write(json.dumps(data, json_write))
                client_socket.send(REPLY + SAPARATE + CODE + SAPARATE + "success")
            else:
                os.rename(r"%s\%s" % (user_name, file_name), r"%s\%s" % (user_name, new_file_name))
                for i in data:
                    if r"%s\%s" % (user_name, file_name) in data[i]["shared_files"]:
                        data[i]["shared_files"][r"%s\%s" % (user_name, new_file_name)] = data[i]["shared_files"][r"%s\%s" % (user_name, file_name)]
                        del data[i]["shared_files"][r"%s\%s" % (user_name, file_name)]
                    elif i == user_name:
                        data[user_name]["shared_files"][new_file_name] = data[user_name]["shared_files"][file_name]
                        del data[user_name]["shared_files"][file_name]
                with open("users.json", "w") as json_write:
                    json_write.write(json.dumps(data, json_write))
                client_socket.send(REPLY + SAPARATE + CODE + SAPARATE + "success")
        else:
            client_socket.send(REPLY + SAPARATE + CODE + SAPARATE + "someone else is working on the file")
    else:
        client_socket.send(REPLY + SAPARATE + CODE + SAPARATE + "file doesn't exist")


def delete(user_name, file_name,  client_socket):
    with open("users.json", "r") as users:
        data = json.load(users)
    if file_name in data[user_name]["files"]:
        os.remove(r"%s\%s" % (user_name, file_name))
        del data[user_name]["files"][file_name]
        with open("users.json", "w") as json_write:
            json_write.write(json.dumps(data, json_write))
        client_socket.send(REPLY + SAPARATE + CODE + SAPARATE + "success")
    elif file_name in data[user_name]["shared_files"]:
        client_socket.send(REPLY + SAPARATE + CODE + SAPARATE + "can't delete shared file")
    else:
        client_socket.send(REPLY + SAPARATE + CODE + SAPARATE + "file doesn't exist")


def main():
    # Open a socket and loop forever while waiting for clients
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_socket.bind((IP, PORT))
        server_socket.listen(QUEUE_SIZE)
        while True:
            client_socket, client_address = server_socket.accept()
            thread = Thread(target=handle_connection,
                            args=(client_socket, client_address))
            thread.start()
    except socket.error as err:
        print 'received socket exception - ' + str(err)
    finally:
        server_socket.close()


def handle_connection(client_socket, client_address):
    try:
        while True:
            data = recv_by_chunk(client_socket).split(SAPARATE)[2].split(FTP_SAPARATE)
            print data
            if data[0] == "login":
                data = recv_by_chunk(client_socket).split(SAPARATE)[2].split(FTP_SAPARATE)
                user_name = data[0]
                password = data[1]
                l1.acquire()
                suc, user_name = log_in(user_name, password, client_socket)
                l1.release()
                if suc:
                    break
            elif data[0] == "sign_on":

                    #client_socket.send("enter a user name and password")
                data = recv_by_chunk(client_socket).split(SAPARATE)[2].split(FTP_SAPARATE)
                print data
                user_name = data[0]
                password = data[1]
                l1.acquire()
                suc, user_name, password = log_on(user_name, password, client_socket)
                l1.release()
            else:
                client_socket.send(REPLY + SAPARATE + CODE + SAPARATE + "wrong operation")
        while True:
            data = recv_by_chunk(client_socket).split(SAPARATE)
            print data
            if data[2] == "exit":
                print  current_user[0]
                user = current_user[0]
                with open("users.json", "r") as users:
                    js_data = json.load(users)
                js_data[user]["state"] = "offline"
                for i in js_data[user]["shared_files"]:
                    if js_data[user]["shared_files"][i] == "working":
                        if len(i.split(r"%s\%s" % ("", ""))) > 1:
                            for j in js_data:
                                if i != user and i in js_data[j]["shared_files"]:
                                    js_data[j]["shared_files"][i] = "open"
                                elif i != user and i.split(r"%s\%s" % ("", ""))[1] in js_data[j]["shared_files"]:
                                    js_data[j]["shared_files"][i.split(r"%s\%s" % ("", ""))[1]] = "open"
                                elif i == user:
                                    js_data[user]["shared_files"][i] = "open"
                        else:
                            for j in js_data:
                                if i != user and i in js_data[j]["shared_files"]:
                                    js_data[j]["shared_files"][i] = "open"
                                elif i != user and (r"%s\%s" % (user, i)) in js_data[j]["shared_files"]:
                                    js_data[j]["shared_files"][(r"%s\%s" % (user, i))] = "open"
                                elif i == user:
                                    js_data[user]["shared_files"][i] = "open"
                with open("users.json", "w") as json_write:
                    json_write.write(json.dumps(js_data, json_write))
                break

            elif data[2] == "save":
                data = recv_by_chunk(client_socket).split(SAPARATE)[2].split(FTP_SAPARATE)
                print data
                l1.acquire()
                save(current_user[0], data[0] + "." + data[1], data[2], client_socket)
                l1.release()
            elif data[2] == "download":
                data = recv_by_chunk(client_socket).split(SAPARATE)[2].split(FTP_SAPARATE)
                print data
                l1.acquire()
                download(current_user[0], data[0], client_socket)
                l1.release()
            elif data[2] == "to_admin":
                data = recv_by_chunk(client_socket).split(SAPARATE)[2].split(FTP_SAPARATE)
                print data
                l1.acquire()
                print current_user[0]
                to_admin(current_user[0], data[0], client_socket)
                l1.release()
            elif data[2] == "share":
                data = recv_by_chunk(client_socket).split(SAPARATE)[2].split(FTP_SAPARATE)
                l1.acquire()
                share(current_user[0], data[0], data[1], client_socket)
                l1.release()
            elif data[2] == "switch":
                data = recv_by_chunk(client_socket).split(SAPARATE)[2].split(FTP_SAPARATE)
                print data
                print 23
                l1.acquire()
                switch(current_user[0], data[0], data[1], client_socket)
                print 23
                l1.release()
            elif data[2] == "rename":
                data = recv_by_chunk(client_socket).split(SAPARATE)[2].split(FTP_SAPARATE)
                l1.acquire()
                rename(current_user[0], data[0], data[1], client_socket)
                l1.release()
                print 456
            elif data[2] == "delete":
                data = recv_by_chunk(client_socket).split(SAPARATE)[2].split(FTP_SAPARATE)
                print data
                l1.acquire()
                delete(current_user[0], data[0], client_socket)
                l1.release()

    except Exception as e:
        print e
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print(exc_type, fname, exc_tb.tb_lineno)
        with open("users.json", "r") as users:
            js_data = json.load(users)
        if current_user[0] != "":
            js_data[current_user[0]]["state"] = "offline"
            with open("users.json", "w") as json_write:
                json_write.write(json.dumps(js_data, json_write))



if __name__ == "__main__":
    main()