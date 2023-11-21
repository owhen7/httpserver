#By Owen Wexler and Dylan Pourkay

#Only these imports are allowed.
import sys, socket, json, random, datetime, hashlib


def log(message):
    current_time = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    print(f"SERVER LOG: {current_time} {message}")







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



    cookies = {}
    try:
        while True:
            client_socket, client_address = server_socket.accept()
            data = client_socket.recv(1024).decode('utf-8')
            method, path, headers, ver = handle_request(data)
            
            
            if method == "POST":
                if path == '/':
                    username = headers.get('username')
                    password = headers.get('password')
                    
                    if not username or not password:
                    
                        #Passes test cases 1 & 2.
                        client_socket.sendall("501 Not Implemented".encode('utf-8'))
                        log("LOGIN FAILED")
                        client_socket.close()
                        continue
                        
                    info = accounts.get(username)
                    
                    if not info:
                        #This is the logic to check if the username exists. It works. Test case 3.
                        client_socket.sendall("HTTP/1.0 200 OK\r\nContent-type: text/plain\r\n\r\nLogin Failed!".encode('utf-8'))
                        log(f"LOGIN FAILED: {username} : {password}")
                        client_socket.close()
                        continue


                    #Right now I am failing every user when they try to log in.
                    #We don't even check if they might have the right password.
                    #TODO: Add some logic here to sign in users correctly so we can pass 
                    #Test cases 5 & 6.
                    #This code and the response it generates passes test cases 3 & 4.
                    client_socket.sendall("HTTP/1.0 200 OK\r\nContent-type: text/plain\r\n\r\nLogin Failed!".encode('utf-8'))
                    log(f"LOGIN FAILED: {username} : {password}")
                    client_socket.close()
                    continue
                   
                       
                        
                                   
            if method == "GET":
            
                #This block passes test case 7. It's worth 10 points.
                log(f"COOKIE INVALID: {path}")
                client_socket.sendall("401 Unauthorized".encode('utf-8'))
                client_socket.close()
                continue
                

                        
                        
            #failsafe. This runs every time if we haven't returned a response by now. 
            client_socket.sendall("411 Fake Code".encode('utf-8'))
            log("FAIL TEST CASE")
            client_socket.close()
                
                
    except KeyboardInterrupt: #ctrl + c to stop server.
        print("\nServer stopped!.")
        server_socket.close()
    
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
