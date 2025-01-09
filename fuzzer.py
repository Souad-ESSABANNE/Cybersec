import socket
import random
import string

def generate_random_input(authenticated=False):
    """Génère des données fuzzées pour les différentes commandes."""
    if authenticated:
        # Commandes disponibles après authentification
        commands = [
            "UPLOAD:",
            "DOWNLOAD:",
            "LIST"
        ]
    else:
        # Toutes les commandes sont disponibles, y compris LOGIN
        commands = [
            "UPLOAD:",
            "DOWNLOAD:",
            "LIST",
            "LOGIN:"
        ]
    
    command = random.choice(commands)
    payload = ''.join(random.choices(string.printable, k=random.randint(1, 512)))
    return f"{command}{payload}".encode()

def send_data(host, port, data):
    """Envoie des données spécifiques à l'application via un socket."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((host, port))
            print(f"[DEBUG] Envoi des données : {data}")
            s.sendall(data)
            
            # Recevoir une réponse
            response = s.recv(1024)
            print(f"[DEBUG] Réponse reçue : {response}")
        except Exception as e:
            print(f"[ERREUR] Exception lors de l'envoi des données : {e}")

def send_authentication(host, port):
    """Envoie une commande de login valide pour s'authentifier."""
    valid_login = "LOGIN:admin:password".encode()  # Commande de login valide
    print("[INFO] Envoi de la commande de login pour authentification...")
    send_data(host, port, valid_login)

def fuzz_commands(host, port, iterations=5, authenticated=False):
    """Effectue le fuzzing des commandes."""
    for i in range(iterations):
        print(f"[TEST] Fuzzing iteration {i + 1}")
        fuzz_input = generate_random_input(authenticated=authenticated)
        send_data(host, port, fuzz_input)
        
        
if __name__ == "__main__":
    host = "127.0.0.1"  # Adresse IP du serveur
    port = 12345        # Port du serveur
    
    # Cas 1 : Fuzzing sans authentification préalable
    print("[INFO] Cas 1 : Fuzzing sans authentification préalable...")
    fuzz_commands(host, port, iterations=5, authenticated=False)
    
    # Cas 2 : Fuzzing avec authentification préalable
    print("[INFO] Cas 2 : Authentification préalable, puis fuzzing...")
    send_authentication(host, port)  # Authentification
    fuzz_commands(host, port, iterations=5, authenticated=True)  # Fuzzing après authentification
    
    print("[INFO] Fuzzing terminé.")
