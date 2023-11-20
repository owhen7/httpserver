#By Owen Wexler and Dylan Pourkay

#Only these imports are allowed.
import sys, socket, json, random, datetime, hashlib


def log(message):
    current_time = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    print(f"SERVER LOG: [{current_time}] {message}")

def generate_sessionID():
    #Return: a random 64 bit integer instring hexadecimal format.
    #For use in a sending users their session ID cookie.

    random_int = random.getrandbits(64)
    sessionID = hex(random_int)[2:]
    return sessionID.zfill(16)

#This function generates a response for the actual HTTP request text that we've recieved from a client connection.
#e.g. GET /images/picture.jpg HTTP/1.1 or something.
def handle_request(request):
    lines = request.split('\r\n')
    method, path, ver = lines[0].split()
    headers = {line.split(': ')[0]: line.split(': ')[1] for line in lines[1:] if line}
    return method, path, headers, ver
    #TODO: handle POST requests for users logging in.
    

    #TODO: also handle GET requests for users requesting files once they've logged in.


    #return "HTTP/1.0 404 Not Found\r\n\r\nFile not found."

#Start the server up and listen for client connections. Stop the server upon recieving ctrl + c.
def start_server(ip, port, accounts, timeout, root_directory):
    #pass
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((ip, int(port)))
    server_socket.listen(1)

    # server_socket.settimeout(timeout*1000) # Set the server to have a timeout in case it doesn't recieve a connection in time.

    # print(f"Server listening on {ip}:{port}")
    cookies = {}
    try:
        while True:
            client_socket, client_address = server_socket.accept()
            data = client_socket.recv(1024).decode('utf-8')
            # print(data)
            method, path, headers, ver = handle_request(data) #Call our method, handle_request() here.
            if method == "POST":
                if path == '/':
                    username = headers.get('username')
                    password = headers.get('password')
                    if not username or not password:
                        client_socket.sendall("501 Not Implemented".encode('utf-8'))
                        log("LOGIN FAILED")
                        continue
                    info = accounts.get(username)
                    if not info:
                        client_socket.sendall(f"HTTP/1.0 200 OK\r\n\r\nLogin failed!".encode('utf-8'))
                        log(f"LOGIN FAILED: {username} : {password}")
                        continue
                    correct_pass, salt = info
                    password += salt
                    m = hashlib.sha256()
                    m.update(password.strip().encode('utf-8'))
                    hexed_pass = m.hexdigest()
                    if correct_pass == hexed_pass:
                        log(f"LOGIN SUCCESSFUL: {username} : {password}")
                        session_id = random.getrandbits(64)
                        cookie = f"sessionID=0x{session_id:x}"
                        cookies[cookie] = [username, datetime.datetime.now()]
                        client_socket.sendall(f"HTTP/1.0 200 OK\r\nSet-Cookie: {cookie}\n\r\n\rLogged in!".encode('utf-8'))
                    else:
                        client_socket.sendall(f"HTTP/1.0 200 OK\r\n\r\nLogin failed!".encode('utf-8'))
                        log(f"LOGIN FAILED: {username} : {password}")
                        continue
            if method == "GET":
                if 'Cookie' not in headers:
                    client_socket.sendall("401 Unauthorized".encode('utf-8'))
                    continue
                info = cookies.get(headers.get('Cookie'))
                if not info:
                    log(f"COOKIE INVALID: {path}")
                    client_socket.sendall("401 Unauthorized".encode('utf-8'))
                    continue
                user, timestamp = info
                if (datetime.datetime.now() - timestamp).seconds > timeout:
                    log(f"SESSION EXPIRED: {user} : {path}")
                    client_socket.sendall("401 Unauthorized".encode('utf-8'))
                try:
                    with open(f"{root_directory}{user}{path}") as f:
                        line = f.readlines()[0].strip()
                        client_socket.sendall(
                            f"HTTP/1.0 200 OK\n\n{line}".encode('utf-8'))
                        log(f"GET SUCCEEDED: {user} : {path}")
                except FileNotFoundError:
                    client_socket.sendall("404 NOT FOUND".encode('utf-8'))
                    log(f"GET FAILED: {user} : {path}")
                    continue
            client_socket.close()
    except KeyboardInterrupt: #ctrl + c to stop server.
        print("\nServer stopped.")
        #server_socket.close()
    
    except TimeoutError:
        print("\nOwen: I made the server timeout here since it didn't receive a connection in a timely manner.")


#Read in the arguments and call start_server().
def main():

    #For example, call using: python server.py 127.0.0.1 8080 accounts.json 5 accounts/
    if len(sys.argv) != 6:
        print("USAGE: python server.py [IP] [PORT] [ACCOUNTS_FILE] [SESSION_TIMEOUT] [ROOT_DIRECTORY]")
        sys.exit(1)

    ip = sys.argv[1]
    port = sys.argv[2]
    accounts_file = sys.argv[3]
    session_timeout = int(sys.argv[4])
    root_directory = sys.argv[5]
    accounts = json.loads(open(accounts_file).readlines()[0])
    # Print the values for demonstration
    # print(f"IP Address: {ip}")
    # print(f"Ports: {port}")
    # print(f"Accounts File Name: {accounts_file}")
    # print(f"Session Timeout: {session_timeout}")
    # print(f"Root Directory Path: {root_directory}")

    #start the server here.
    start_server(ip, port, accounts, session_timeout, root_directory)


if __name__ == "__main__":
    main()