
import java.security.SecureRandom
import java.text.DecimalFormat
import java.util.*
import kotlin.experimental.xor



object Encryption {
    private var aes: AES? = null
    private lateinit var plaintext: ByteArray
    private lateinit var cipherText: ByteArray
    private val df = DecimalFormat()
    fun ECBEncryptionWithKey(sc: Scanner) {
        df.maximumFractionDigits = 8
        while (true) {
            try {
                print("Plain text: ")
                var plainText: String = sc.nextLine()
                print("Key: ")
                val keyInput: String = sc.nextLine()
                val inputText = pushDataToBlock(plainText).toByteArray()
                var key: ByteArray
                key = keyInput.toByteArray()
                aes = AES(key,null)
                var startTime = System.nanoTime()
                println("Plain text: $plainText")
                val cipherBytes = aes!!.ECB_encrypt(inputText)
                val a: String = Base64.getEncoder().encodeToString(cipherBytes)
                println("Cipher text: " + a.trim { it <= ' ' })
                var endTime = System.nanoTime()
                println("ECB Encryption | " + df.format((endTime - startTime).toFloat() / 1000000.00) + "ms")
                startTime = System.nanoTime()
                println("Cipher text: " + a.trim { it <= ' ' })
                plainText = String(aes!!.ECB_decrypt(cipherBytes!!)!!)
                println("Plain text: $plainText")
                endTime = System.nanoTime()
                println("ECB Decryption | " + df.format((endTime - startTime).toFloat() / 1000000.00) + "ms")
                plaintext = inputText
                cipherText = cipherBytes
                break
            } catch (e: Exception) {
                println("Vui lòng nhập lại: ")
                println(e.message)
            }
        }
    }

    fun ECBEncryptionWithRandomKey(sc: Scanner) {
        df.maximumFractionDigits = 8
        while (true) {
            try {
                print("Plain text: ")
                var plainText: String = sc.nextLine()
                val inputText = pushDataToBlock(plainText).toByteArray()
                var key: ByteArray?
                key = makeRandomKey()
                System.out.println("Random Key: " + Base64.getEncoder().encodeToString(key))
                aes = AES(key)
                var startTime = System.nanoTime()
                val cipherBytes = aes!!.ECB_encrypt(inputText)
                val a: String = Base64.getEncoder().encodeToString(cipherBytes)
                println("Cipher text: " + a.trim { it <= ' ' })
                var endTime = System.nanoTime()
                println("ECB Encryption | " + df.format((endTime - startTime).toFloat() / 1000000.00) + "ms")
                startTime = System.nanoTime()
                println("Cipher text: " + a.trim { it <= ' ' })
                plainText = String(aes!!.ECB_decrypt(cipherBytes!!)!!)
                println("Plain text: $plainText")
                endTime = System.nanoTime()
                println("ECB Decryption | " + df.format((endTime - startTime).toFloat() / 1000000.00) + "ms")
                plaintext = inputText
                cipherText = cipherBytes
                break
            } catch (e: Exception) {
                println("Vui lòng nhập lại: ")
                println(e.message)
            }
        }
    }

    fun CBCEncryptionWithKey(sc: Scanner) {
        df.maximumFractionDigits = 8
        while (true) {
            try {
                print("Plain text: ")
                var plainText: String = sc.nextLine()
                print("Key: ")
                val keyInput: String = sc.nextLine()
                print("Initialisation vector: ")
                val ivInput: String = sc.nextLine()
                val inputText = pushDataToBlock(plainText).toByteArray()
                var key: ByteArray
                key = keyInput.toByteArray()
                val iv = ivInput.toByteArray()
                aes = AES(key, iv)
                var startTime = System.nanoTime()
                println("Plain text: $plainText")
                val cipherBytes = aes!!.CBC_encrypt(inputText)
                val a: String = Base64.getEncoder().encodeToString(cipherBytes)
                println("Cipher text: " + a.trim { it <= ' ' })
                var endTime = System.nanoTime()
                println("CBC Encryption | " + df.format((endTime - startTime).toFloat() / 1000000.00) + "ms")
                startTime = System.nanoTime()
                println("Cipher text: " + a.trim { it <= ' ' })
                plainText = String(aes!!.CBC_encrypt(cipherBytes!!)!!)
                println("Plain text: $plainText")
                endTime = System.nanoTime()
                println("CBC Decryption | " + df.format((endTime - startTime).toFloat() / 1000000.00) + "ms")
                plaintext = inputText
                cipherText = cipherBytes
                break
            } catch (e: Exception) {
                println("Vui lòng nhập lại: ")
                println(e.message)
            }
        }
    }

    fun CBCEncryptionWithRandomKey(sc: Scanner) {
        df.maximumFractionDigits = 8
        while (true) {
            try {
                print("Plain text: ")
                var plainText: String = sc.nextLine()
                val inputText = pushDataToBlock(plainText).toByteArray()
                var key: ByteArray?
                key = makeRandomKey()
                System.out.println("Random Key: " + Base64.getEncoder().encodeToString(key))
                val iv = makeRandomIv()
                aes = AES(key, iv)
                var startTime = System.nanoTime()
                val cipherBytes = aes!!.CBC_encrypt(inputText)
                val a: String = Base64.getEncoder().encodeToString(cipherBytes)
                println("Cipher text: " + a.trim { it <= ' ' })
                val b: String = Base64.getEncoder().encodeToString(iv)
                println("Iv: " + b.trim { it <= ' ' })
                var endTime = System.nanoTime()
                println("CBC Encryption | " + df.format(((endTime - startTime).toFloat() / 1000000000f).toDouble()) + "ms")
                startTime = System.nanoTime()
                println("Cipher text: " + a.trim { it <= ' ' })
                plainText = String(aes!!.CBC_decrypt(cipherBytes!!)!!)
                println("Plain text: $plainText")
                endTime = System.nanoTime()
                println("CBC Decryption | " + df.format(((endTime - startTime).toFloat() / 1000000000f).toDouble()) + "ms")
                plaintext = inputText
                cipherText = cipherBytes
                break
            } catch (e: Exception) {
                println("Vui lòng nhập lại: ")
                println(e.message)
            }
        }
    }

    fun diffBit() {
        println("Plain text: " + String(plaintext))
        System.out.println("Cipher text: " + Base64.getEncoder().encodeToString(cipherText))
        println("Số bits khác biệt: " + numBitDiff(plaintext, cipherText))
    }

    private fun pushDataToBlock(text: String): String {
        var text = text
        val spaceNum = if (text.toByteArray().size % 16 == 0) 0 else 16 - text.toByteArray().size % 16
        val textBuilder = StringBuilder(text)
        textBuilder.append(" ".repeat(spaceNum))
        text = textBuilder.toString()
        return text
    }

    private fun makeRandomKey(): ByteArray? {
        val random = SecureRandom()
        val length: Int = Random().nextInt(2)
        return when (length) {
            1 -> {
                val bytes = ByteArray(24)
                random.nextBytes(bytes)
                bytes
            }
            2 -> {
                val bytes = ByteArray(32)
                random.nextBytes(bytes)
                bytes
            }
            else -> {
                val bytes = ByteArray(16)
                random.nextBytes(bytes)
                bytes
            }
        }
    }

    private fun makeRandomIv(): ByteArray {
        var key = ""
        for (i in 0..0) key += java.lang.Long.toHexString(java.lang.Double.doubleToLongBits(Math.random()))
        return key.toByteArray()
    }

    private fun numBitDiff(a: ByteArray, b: ByteArray?): Int {
        var num = 0
        val result = ByteArray(Math.min(a.size, b!!.size))
        for (j in result.indices) {
            var xorInternal = a[j] xor b[j]
            while (xorInternal > 0) {
                val temp = xorInternal % 2
                if (temp == 1) num++
                xorInternal= (xorInternal/2).toByte()
            }
        }
        return num
    }
}