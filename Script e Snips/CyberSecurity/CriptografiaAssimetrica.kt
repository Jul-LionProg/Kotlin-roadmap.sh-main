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

    fun generateSymetricKey(): SecretKey {
        val keyGen = KeyGenerator.getInstance(ALGORITHM)
        keyGen.init(256)
        return keyGen.generateKey()
    }

    fun encryptWithPublicKey(data: String, publicKey: PublicKey): String {
        val cipher = Cipher.getInstance(RSA_ALGORITHM)
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        val encryptedBytes = cipher.doFinal(data.toByteArray())
        return Base64.getEncoder().encodeToString(encryptedBytes)
    }

    fun decryptWithPrivateKey(data: String, privateKey: PrivateKey): String {
        val cipher = Cipher.getInstance(RSA_ALGORITHM)
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        val decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(data))
        return String(decryptedBytes)
    }

    fun decryptWithSymetricKey(data: String, key: SecretKey): String {
        val cipher = Cipher.getInstance(ALGORITHM)
        cipher.init(Cipher.DECRYPT_MODE, key)
        val decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(data))
        return String(decryptedBytes)
    }

    fun encryptWithSymetricKey(data: String, key: SecretKey): String {
        val cipher = Cipher.getInstance(ALGORITHM)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val encryptedBytes = cipher.doFinal(data.toByteArray())
        return Base64.getEncoder().encodeToString(encryptedBytes)
    }

    fun encryptSymmetricKey(symmetricKey: SecretKey, publicKey: PublicKey): String {
        val cipher = Cipher.getInstance(RSA_ALGORITHM)
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        val encryptedBytes = cipher.doFinal(symmetricKey.encoded)
        return Base64.getEncoder().encodeToString(encryptedBytes)
    }

    fun decryptSymmetricKey(data: String, privateKey: PrivateKey): SecretKey {
        val cipher = Cipher.getInstance(RSA_ALGORITHM)
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        val decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(data))
        return SecretKeySpec(decryptedBytes, ALGORITHM)
    }
}

fun main () {
    // Gera um par de chaves RSA
    val keyPair = AsymmetricCryptoUtil.generateKeyPair()
    val publicKey = keyPair.public
    val privateKey = keyPair.private

    // Gera uma chave simétrica
    val symetricKey = AsymmetricCryptoUtil.generateSymetricKey()

    // Encripta a chave simétrica com a chave publica
    val encryptedSymetricKey = AsymmetricCryptoUtil.encryptSymmetricKey(symetricKey, publicKey)

    // Decripta a chave simétrica com a chave privada
    val decryptedSymetricKey = AsymmetricCryptoUtil.decryptSymmetricKey(encryptedSymetricKey, privateKey)

    // Encripta a mensagem com a chave simétrica
    val encryptedMessage = AsymmetricCryptoUtil.encryptWithSymetricKey("Hello World", decryptedSymetricKey)

    // Decripta a mensagem com a chave simétrica
    val decryptedMessage = AsymmetricCryptoUtil.decryptWithSymetricKey(encryptedMessage, decryptedSymetricKey)
}

// Perguntas levantadas
/*
1. O que é criptografia assimétrica e como ela é usada em segurança de dados?
   A criptografia assimétrica usa um par de chaves, uma pública e outra privada. A chave pública criptografa dados, e a chave privada descriptografa. Isso permite que qualquer pessoa envie uma mensagem segura para o destinatário, pois só o destinatário tem a chave privada necessária para a descriptografia.

2. Qual a vantagem de usar a criptografia assimétrica em comparação à simétrica?
   A vantagem principal é a capacidade de compartilhar a chave pública abertamente, enquanto a chave privada permanece secreta, solucionando o problema da troca segura de chaves que é um desafio na criptografia simétrica.

3. Por que o RSA é uma escolha popular para criptografia assimétrica?
   O RSA é amplamente usado devido à sua robustez e segurança, baseada na dificuldade de fatorar grandes números primos. Isso torna ataques de força bruta inviáveis para chaves de tamanho adequado.

4. Como funciona o algoritmo AES e por que é usado juntamente com RSA?
   O AES é um algoritmo de criptografia simétrica rápido e eficiente para grandes volumes de dados. Em combinação com RSA, AES criptografa os dados reais e RSA criptografa a chave AES, unindo velocidade e segurança na troca de chaves.

5. O que faz o método generateKeyPair() na classe CryptographyUtil?
   O método generateKeyPair() gera um par de chaves RSA (pública e privada) usando um gerador de chaves configurado com 2048 bits, considerado seguro para a maioria das aplicações.

6. Como a chave simétrica AES é gerada no script?
   A chave AES é gerada pelo método generateSymmetricKey(), que usa um gerador de chaves configurado com 256 bits, garantindo forte segurança para a criptografia de dados.

7. Explique o propósito do método encryptWithPublicKey().
   O método encryptWithPublicKey() criptografa dados com a chave pública RSA, inicializando um objeto Cipher no modo de criptografia e retornando uma string Base64 dos bytes criptografados.

8. Qual é a função do método decryptWithPrivateKey()?
   O método decryptWithPrivateKey() descriptografa dados com a chave privada RSA, inicializando um objeto Cipher no modo de descriptografia e retornando a mensagem original como string.

9. Por que é necessário usar Base64 na criptografia e descriptografia?
   Base64 converte dados binários em texto, permitindo a transmissão ou armazenamento em sistemas que não suportam dados binários diretamente, garantindo que dados criptografados possam ser enviados por qualquer meio de comunicação que suporte texto.

10. Descreva o processo de criptografia de uma mensagem com a chave pública RSA.
    Um objeto Cipher é inicializado no modo de criptografia com a chave pública RSA. Os dados são convertidos em bytes e processados pelo Cipher, resultando em bytes criptografados que são então codificados em Base64 para formar a mensagem criptografada final.

11. Como o método decryptWithSymmetricKey() funciona para descriptografar dados?
    O método decryptWithSymmetricKey() inicializa um objeto Cipher no modo de descriptografia com a chave secreta AES, decodifica os dados criptografados em Base64, processa com o Cipher e retorna os bytes descriptografados como string.

12. Qual é o propósito do método encryptSymmetricKey()?
    O método encryptSymmetricKey() criptografa uma chave secreta AES com a chave pública RSA, permitindo a transmissão segura da chave AES, que só pode ser descriptografada com a chave privada correspondente.

13. Explique como o método decryptSymmetricKey() descriptografa uma chave secreta.
    O método decryptSymmetricKey() usa a chave privada RSA para descriptografar uma chave secreta AES criptografada com a chave pública, decodifica a chave criptografada em Base64 e processa com um objeto Cipher no modo de descriptografia, retornando a chave AES original.
