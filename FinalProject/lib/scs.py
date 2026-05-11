import key_generation

def main():
    print("Generating RSA key paris for users in the secure communication system\n")

    key_generation.gen_rsa_key_pair("Alice") #generates keys for Alice
    key_generation.gen_rsa_key_pair("Bob") #generates keys for Bob

    print("All RSA keys have been generated.")

if __name__ == "__main__":
    main()