#Generation of RSA key pairs for two users in a secure communication system
#Will use Alice and Bob as the two users

from Crypto.PublicKey import RSA

#user -> a string; name of the user
#key_size -> an int; default RSA key size in bits
def gen_rsa_key_pair(user, key_size=2048): 
    key = RSA.generate(key_size) #Generates a new RSA private/public key pair

    private_key = key.export_key() #exports a private key in PEM format
    public_key = key.publickey().export_key() #exports a public key in PEM format

    private_key_file = f"../{user}_private.pem" #Creates a local file for private key
    public_key_file = f"../{user}_public.pem" #Creates a local file for public key

    #Saves the private key to local file
    with open(private_key_file, "wb") as private_file:
        private_file.write(private_key)
    #Saves the public key to local file
    with open(public_key_file, "wb") as public_file:
        public_file.write(public_key)

    print(f"{user}'s RSA key pair generated successfully.")
    print(f"Private key saved in: {private_key_file}")
    print(f"Public key saved in:  {public_key_file}")