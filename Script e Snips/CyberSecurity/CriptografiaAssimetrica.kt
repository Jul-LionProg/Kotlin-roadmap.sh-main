// Script apenas para entender a logica. O objetivo é o uso da criptografia simetrica e assimetrica, onde envio uma chave AES, criptografando com a chave publica, e descriptografando com a chave privada, ambas chaves RSA. Após isso, encripto uma mensagem usando a chave AES, e descriptogradando com a mesma.

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.KeyGenerator
import javax.crypto.spec.SecretKeySpec
import java.util.Base64

object AsymmetricCryptoUtil {
    private const val RSA_ALGORITHM = "RSA"
    private const val ALGORITHM = "AES"

    fun generateKeyPair(): KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance(RSA_ALGORITHM)
        keyPairGenerator.initialize(2048)
        return keyPairGenerator.generateKeyPair()
    }
