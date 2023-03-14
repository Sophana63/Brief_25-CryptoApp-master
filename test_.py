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
    print(ciphertext, decryptedtext)
    if plaintext == decryptedtext:
        print("CaesarCipher Test: ok, it's same!")


if __name__ == "__main__":
    test_aes()
    test_md5()
    test_sha()
    test_caesar_cipher()