"""
Les fonctions à tester sont les méthodes 'encrypt' et 'decrypt'
des classes contenues dans les fichiers dont le nom se termine
par 'algo.py'. À noter que certaines classes n'ont pas de méthode
decrypt, ou uniquement une méthode vide.

Pour savoir quelles sont les entrées et/ou le format des clés attendus
par ces différentes fonctions de cryptage/décryptage, vous pouvez lancer
l'application et lire les encadrés d'information à droite, et faire des
recherches.

Pour lancer tous les tests contenus dans ce fichier, utilisez
la commande pytest <nom de ce script>
"""
from crypto_app.enigmam3_algo import EnigmaM3
from crypto_app.aes_algo import AdvancedEncryptionStandard
from crypto_app.md5_algo import MD5
from crypto_app.sha_algo import SHA
from crypto_app.caesarcipher_algo import CaesarCipher
from crypto_app.vigenerecipher_algo import VigenereCipher
from crypto_app.des_algo import DES
from crypto_app.blowfish_algo import Blowfish
from crypto_app.rsa_algo_v2 import RSAAlgo

def test_enigma():
    """
    Un exemple de fonction de test, ici avec le cryptage
    d'Enigma.
    """
    enigma = EnigmaM3()
    msg = "Message"
    key = [
        ('A', 'C', 'N'),
        (2, 4, 1),
        ('F', 'H', 'K'),
        [('A', 'K')]
    ]

    encrypted = enigma.encrypt(msg, key)
    assert encrypted == "FUTALDK"
    decrypted = enigma.decrypt(encrypted, key)
    assert decrypted == "MESSAGE"

def test_aes():
    enigma_aes = AdvancedEncryptionStandard()
    plaintext = "This is a test message"
    key = "1234567890123456"
    ciphertext = enigma_aes.encrypt(plaintext, key)
    decryptedtext = enigma_aes.decrypt(ciphertext, key)
    if plaintext == decryptedtext:
        print("AES Test: ok, it's same!")

def test_md5():
    enigma_md5 = MD5()
    message = "Pierre qui roule, n'amasse pas mousse"
    expected_hash = "2371e7e3cc3f124e66f695c92b13aca4"  # MD5 hash of the message
    ciphertext = enigma_md5.encrypt(message)    
    if ciphertext == expected_hash:
        print("MD5 Test: ok, it's same!")

def test_sha():
    enigma_sha = SHA()
    message = "Quand il n'y a plus d'arbres, il n'y a plus de singes."
    expected_hash = "6a1f0b34a2150aa8100e20aa1f5ca81ba10d1c424b5cbc3fa9b8cde834834cce54c29ea1c79b4a5a278d00c11473509b7c6a73d9ee133f64e048900d0cb5945c"  # SHA-512 hash of the message
    actual_hash = enigma_sha.encrypt(message)
    if actual_hash == expected_hash:
        print("SHA Test: ok, it's same!")

def test_caesar_cipher():
    enigma_caesar = CaesarCipher()
    plaintext = "La meilleure pomme est sur la plus haute branche."
    key = 5
    ciphertext = enigma_caesar.encrypt(plaintext, key)
    decryptedtext = enigma_caesar.decrypt(ciphertext, key)
    if plaintext == decryptedtext:
        print("CaesarCipher Test: ok, it's same!")

def test_vigenere_cipher():

    vigenere = VigenereCipher()
    # Test encryption and decryption with a key of "secret"
    message = "hello world"
    key = "secret"
    encrypted = vigenere.encrypt(message, key)
    decrypted = vigenere.decrypt(encrypted, key)
    assert decrypted == message, f"Expected decrypted message '{message}', but got '{decrypted}'"

    # Test encryption and decryption with a key of "password"
    message = "this is a secret message"
    key = "password"
    encrypted = vigenere.encrypt(message, key)
    decrypted = vigenere.decrypt(encrypted, key)
    assert decrypted == message, f"Expected decrypted message '{message}', but got '{decrypted}'"

    # Test error handling for invalid inputs
    assert not vigenere.encrypt(123), "Expected error message for invalid message input"
    assert not vigenere.encrypt("hello", 123), "Expected error message for invalid key input"
    assert not vigenere.encrypt("hello", ""), "Expected error message for empty key input"

    print("VigenereCipher Test: All tests passed!")

def test_des():
    des = DES()

    # Test encryption and decryption with valid inputs
    message = "hello world"
    key = "abcdefgh"
    encrypted = des.encrypt(message, key)
    decrypted = des.decrypt(encrypted, key)
    assert decrypted == message, f"Expected decrypted message '{message}', but got '{decrypted}'"

    # Test encryption and decryption with invalid inputs
    message = 12345
    key = "abcdefghijklmnop"
    encrypted = des.encrypt(message, key)
    decrypted = des.decrypt(encrypted, key)
    assert decrypted == False, "Expected decryption to fail due to invalid message and key"

    message = "hello world"
    key = "abcdefghijklmnopqrstuvwx"
    encrypted = des.encrypt(message, key)
    decrypted = des.decrypt(encrypted, key)
    assert decrypted == message

    print("DES Test: All tests passed!")

def test_blowfish():

    message = "This is a test message"
    key = "secretkey"

    bf = Blowfish()

    encrypted_message = bf.encrypt(message, key)
    decrypted_message = bf.decrypt(encrypted_message, key)

    assert decrypted_message == message

    print("Blowfish Test: All tests passed!")


def test_RSAAlgo():    
    message = "Hello World!"
    rsa_algo = RSAAlgo()
    private_key, public_key = rsa_algo.generateKeysPair()
    encrypted_message = rsa_algo.encrypt(message, public_key)
    decrypted_message = rsa_algo.decrypt(encrypted_message, private_key)
    assert decrypted_message == message
    print("RSA Test: All tests passed!")

