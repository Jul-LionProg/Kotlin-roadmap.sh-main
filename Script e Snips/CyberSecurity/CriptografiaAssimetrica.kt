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

    fun encryptWithSymetricKey(data: String, key: SecretKey): String {
        val cipher = Cipher.getInstance(ALGORITHM)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val encryptedBytes = cipher.doFinal(data.toByteArray())
        return Base64.getEncoder().encodeToString(encryptedBytes)
    }

    fun decryptWithSymetricKey(data: String, key: SecretKey): String {
        val cipher = Cipher.getInstance(ALGORITHM)
        cipher.init(Cipher.DECRYPT_MODE, key)
        val decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(data))
        return String(decryptedBytes)
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

14. Quais são as etapas envolvidas na descriptografia de uma mensagem no script?
    Primeiro, a mensagem criptografada em Base64 é decodificada. Em seguida, a mensagem decodificada é descriptografada com a chave privada RSA para recuperar os dados originais. Se uma chave AES foi usada, a chave AES é primeiro descriptografada com a chave privada RSA, depois os dados são descriptografados com a chave AES.

15. Como a criptografia RSA garante a segurança na transmissão de chaves AES?
    A chave pública RSA criptografa a chave AES, garantindo que apenas o destinatário com a chave privada RSA possa descriptografar e acessar a chave AES, proporcionando uma camada adicional de segurança na transmissão de chaves.

16. Qual é a importância de usar tamanhos de chave adequados em RSA e AES?
    Tamanhos de chave maiores aumentam a segurança criptográfica. Em RSA, chaves de 2048 bits são comumente usadas para um bom equilíbrio entre segurança e desempenho. Em AES, chaves de 256 bits são preferidas para máxima segurança.

17. O que acontece se a chave privada RSA for comprometida?
    Se a chave privada RSA for comprometida, qualquer pessoa com essa chave pode descriptografar dados criptografados com a chave pública correspondente, comprometendo a segurança das comunicações.

18. Por que é recomendado usar um gerador de números aleatórios seguro para gerar chaves criptográficas?
    Um gerador de números aleatórios seguro garante que as chaves geradas sejam imprevisíveis e resistentes a ataques, aumentando a segurança da criptografia.

19. Quais são os principais casos de uso para a criptografia assimétrica?
    Criptografia assimétrica é usada para troca segura de chaves, assinaturas digitais, autenticação e criptografia de dados confidenciais onde a troca segura de chaves é crucial.

20. Como a combinação de criptografia simétrica e assimétrica melhora a eficiência e segurança?
    A criptografia simétrica é eficiente para grandes volumes de dados, enquanto a assimétrica garante a segurança na troca de chaves. Combiná-las permite criptografar dados rapidamente e trocar chaves de forma segura.

21. Qual é o papel do método decryptSymmetricKey() na combinação de RSA e AES?
    O método decryptSymmetricKey() permite que a chave AES, criptografada com a chave pública RSA, seja descriptografada com a chave privada RSA, garantindo que apenas o destinatário pretendido possa acessar a chave AES para descriptografar os dados.

22. Quais são as limitações da criptografia assimétrica?
    Criptografia assimétrica é mais lenta que a simétrica e requer maiores recursos computacionais. Portanto, não é ideal para criptografar grandes volumes de dados, mas excelente para troca segura de chaves e autenticação.

23. Como a integridade dos dados é mantida durante a criptografia e descriptografia?
    Durante a criptografia e descriptografia, qualquer alteração nos dados criptografados resultará em uma falha na descriptografia, indicando que a integridade dos dados foi comprometida.

24. Por que é importante inicializar corretamente os objetos Cipher no modo apropriado?
    Inicializar corretamente os objetos Cipher no modo apropriado (criptografia ou descriptografia) é crucial para garantir que os dados sejam processados corretamente e a segurança da criptografia seja mantida.

25. Quais são os riscos de usar chaves criptográficas fracas ou previsíveis?
    Chaves fracas ou previsíveis são suscetíveis a ataques de força bruta ou outros métodos de quebra de criptografia, comprometendo a segurança dos dados criptografados.

26. O que é a codificação Base64 e por que é utilizada na criptografia?
    Base64 é um método de codificação que converte dados binários em texto ASCII. É usado na criptografia para garantir que os dados criptografados possam ser transmitidos ou armazenados em sistemas que não suportam dados binários.

27. Como a criptografia ponta a ponta garante a segurança das comunicações?
    Na criptografia ponta a ponta, os dados são criptografados no dispositivo do remetente e só podem ser descriptografados no dispositivo do destinatário, garantindo que nenhum intermediário possa acessar os dados.

28. Qual é a diferença entre criptografia e hashing?
    Criptografia é o processo de transformar dados legíveis em um formato ilegível que pode ser revertido com uma chave de descriptografia. Hashing é uma transformação unidirecional que converte dados em um valor fixo (hash) que não pode ser revertido.

29. Quais são os desafios na implementação de criptografia assimétrica?
    Desafios incluem a gestão segura de chaves, o desempenho computacional devido à natureza intensiva do algoritmo e garantir que as chaves privadas não sejam comprometidas.

30. Como a criptografia pode ser integrada a outros métodos de segurança, como assinaturas digitais?
    A criptografia pode ser usada juntamente com assinaturas digitais para autenticação e integridade de dados. Uma assinatura digital é criada criptografando um hash dos dados com a chave privada do remetente, que pode ser verificado pelo destinatário com a chave pública do remetente.
*/
