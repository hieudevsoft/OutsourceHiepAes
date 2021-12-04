import java.io.ByteArrayOutputStream
import java.io.IOException
import java.util.*
import kotlin.experimental.and
import kotlin.experimental.xor


class AES {
    constructor(key: ByteArray?){
        if (key != null) {
            init(key, null)
        }
    }
    constructor(key: ByteArray?, iv: ByteArray?){
        if (key != null) {
            init(key, iv)
        }
    }

    private var currentRound = 0
    private var Nb = 4
    private var Nr = 0
    private var Nk = 0
    private lateinit var state: Array<Array<IntArray>>
    private lateinit var w: IntArray
    private lateinit var key: IntArray
    private lateinit var iv: ByteArray

    private fun init(key: ByteArray, iv: ByteArray?) {
        if (iv != null) {
            this.iv = iv
        }
        this.key = IntArray(key.size)
        for (i in key.indices) {
            this.key[i] = key[i].toInt()
        }
        Nb = 4
        when (key.size) {
            16 -> {
                Nr = 10
                Nk = 4
            }
            24 -> {
                Nr = 12
                Nk = 6
            }
            32 -> {
                Nr = 14
                Nk = 8
            }
            else -> throw IllegalArgumentException("Chỉ hỗ trợ 128, 192 and 256 bit keys!")
        }
        state = Array(2) { Array(4) { IntArray(Nb) } }
        w = IntArray(Nb * (Nr + 1))
        expandKey()
    }
    private fun addRoundKey(s: Array<IntArray>, round: Int): Array<IntArray>? {
        for (c in 0 until Nb) {
            for (r in 0..3) {
                s[r][c] = s[r][c] xor (w[round * Nb + c] shl r * 8 ushr 24)
            }
        }
        return s
    }

    private fun cipher(`in`: Array<IntArray>, out: Array<IntArray>): Array<IntArray>? {
        for (i in `in`.indices) {
            for (j in `in`.indices) {
                out[i][j] = `in`[i][j]
            }
        }
        currentRound = 0
        addRoundKey(out, currentRound)
        currentRound = 1
        while (currentRound < Nr) {
            subBytes(out)
            shiftRows(out)
            mixColumns(out)
            addRoundKey(out, currentRound)
            currentRound++
        }
        subBytes(out)
        shiftRows(out)
        addRoundKey(out, currentRound)
        return out
    }
    private fun decipher(`in`: Array<IntArray>, out: Array<IntArray>): Array<IntArray>? {
        for (i in `in`.indices) {
            for (j in `in`.indices) {
                out[i][j] = `in`[i][j]
            }
        }
        currentRound = Nr
        addRoundKey(out, currentRound)
        currentRound = Nr - 1
        while (currentRound > 0) {
            invShiftRows(out)
            invSubBytes(out)
            addRoundKey(out, currentRound)
            invMixColumns(out)
            currentRound--
        }
        invShiftRows(out)
        invSubBytes(out)
        addRoundKey(out, currentRound)
        return out
    }

    private fun encrypt(text: ByteArray): ByteArray? {
        require(text.size == 16) { "Chỉ 16-bytes block mới được phép mã hóa" }
        val out = ByteArray(text.size)
        for (i in 0 until Nb) {
            for (j in 0..3) {
                state[0][j][i] = (text[i * Nb + j] and 0xff.toByte()).toInt()
            }
        }
        cipher(state[0], state[1])
        for (i in 0 until Nb) {
            for (j in 0..3) {
                out[i * Nb + j] = (state[1][j][i] and 0xff).toByte()
            }
        }
        return out
    }
    private fun decrypt(text: ByteArray): ByteArray? {
        require(text.size == 16) { "Chỉ 16-bytes block mới được phép giải mã" }
        val out = ByteArray(text.size)
        for (i in 0 until Nb) { // columns
            for (j in 0..3) { // rows
                state[0][j][i] = (text[i * Nb + j] and 0xff.toByte()).toInt()
            }
        }
        decipher(state[0], state[1])
        for (i in 0 until Nb) {
            for (j in 0..3) {
                out[i * Nb + j] = (state[1][j][i] and 0xff).toByte()
            }
        }
        return out
    }

    private fun invMixColumns(state: Array<IntArray>): Array<IntArray>? {
        var temp0: Int
        var temp1: Int
        var temp2: Int
        var temp3: Int
        for (c in 0 until Nb) {
            temp0 = mult(0x0e, state[0][c]) xor mult(0x0b, state[1][c]) xor mult(0x0d, state[2][c]) xor mult(
                0x09,
                state[3][c]
            )
            temp1 = mult(0x09, state[0][c]) xor mult(0x0e, state[1][c]) xor mult(0x0b, state[2][c]) xor mult(
                0x0d,
                state[3][c]
            )
            temp2 = mult(0x0d, state[0][c]) xor mult(0x09, state[1][c]) xor mult(0x0e, state[2][c]) xor mult(
                0x0b,
                state[3][c]
            )
            temp3 = mult(0x0b, state[0][c]) xor mult(0x0d, state[1][c]) xor mult(0x09, state[2][c]) xor mult(
                0x0e,
                state[3][c]
            )
            state[0][c] = temp0
            state[1][c] = temp1
            state[2][c] = temp2
            state[3][c] = temp3
        }
        return state
    }
    private fun invShiftRows(state: Array<IntArray>): Array<IntArray>? {
        var temp1: Int
        var temp2: Int
        val temp3: Int
        var i: Int
        temp1 = state[1][Nb - 1]
        i = Nb - 1
        while (i > 0) {
            state[1][i] = state[1][(i - 1) % Nb]
            i--
        }
        state[1][0] = temp1
        temp1 = state[2][Nb - 1]
        temp2 = state[2][Nb - 2]
        i = Nb - 1
        while (i > 1) {
            state[2][i] = state[2][(i - 2) % Nb]
            i--
        }
        state[2][1] = temp1
        state[2][0] = temp2
        temp1 = state[3][Nb - 3]
        temp2 = state[3][Nb - 2]
        temp3 = state[3][Nb - 1]
        i = Nb - 1
        while (i > 2) {
            state[3][i] = state[3][(i - 3) % Nb]
            i--
        }
        state[3][0] = temp1
        state[3][1] = temp2
        state[3][2] = temp3
        return state
    }
    private fun invSubBytes(state: Array<IntArray>): Array<IntArray>? {
        for (i in 0..3) {
            for (j in 0 until Nb) {
                state[i][j] = invSubWord(state[i][j]) and 0xFF
            }
        }
        return state
    }

    private fun invSubWord(word: Int): Int {
        var subWord = 0
        var i = 24
        while (i >= 0) {
            val `in` = word shl i ushr 24
            subWord = subWord or (AesHelper.rsBox[`in`] shl 24 - i)
            i -= 8
        }
        return subWord
    }
    private fun expandKey(): IntArray? {
        var temp: Int
        var i = 0
        while (i < Nk) {
            w[i] = 0x00000000
            w[i] = w[i] or (key[4 * i] shl 24)
            w[i] = w[i] or (key[4 * i + 1] shl 16)
            w[i] = w[i] or (key[4 * i + 2] shl 8)
            w[i] = w[i] or key[4 * i + 3]
            i++
        }
        i = Nk
        while (i < Nb * (Nr + 1)) {
            temp = w[i - 1]
            if (i % Nk == 0) {
                temp = subWord(rotWord(temp)) xor (AesHelper.rCon[i / Nk] shl 24)
            } else if (Nk > 6 && i % Nk == 4) {
                temp = subWord(temp)
            } else {
            }
            w[i] = w[i - Nk] xor temp
            i++
        }
        return w
    }
    private fun mixColumns(state: Array<IntArray>): Array<IntArray>? {
        var temp0: Int
        var temp1: Int
        var temp2: Int
        var temp3: Int
        for (c in 0 until Nb) {
            temp0 = mult(0x02, state[0][c]) xor mult(0x03, state[1][c]) xor state[2][c] xor state[3][c]
            temp1 = state[0][c] xor mult(0x02, state[1][c]) xor mult(0x03, state[2][c]) xor state[3][c]
            temp2 = state[0][c] xor state[1][c] xor mult(0x02, state[2][c]) xor mult(0x03, state[3][c])
            temp3 = mult(0x03, state[0][c]) xor state[1][c] xor state[2][c] xor mult(0x02, state[3][c])
            state[0][c] = temp0
            state[1][c] = temp1
            state[2][c] = temp2
            state[3][c] = temp3
        }
        return state
    }
    private fun mult(a: Int, b: Int): Int {
        var a = a
        var b = b
        var sum = 0
        while (a != 0) {
            if (a and 1 != 0) {
                sum = sum xor b
            }
            b = xtime(b)
            a = a ushr 1
        }
        return sum
    }

    private fun rotWord(word: Int): Int {
        return word shl 8 or (word and -0x1000000 ushr 24)
    }
    private fun shiftRows(state: Array<IntArray>): Array<IntArray>? {
        var temp1: Int
        var temp2: Int
        val temp3: Int
        var i: Int
        temp1 = state[1][0]
        i = 0
        while (i < Nb - 1) {
            state[1][i] = state[1][(i + 1) % Nb]
            i++
        }
        state[1][Nb - 1] = temp1
        temp1 = state[2][0]
        temp2 = state[2][1]
        i = 0
        while (i < Nb - 2) {
            state[2][i] = state[2][(i + 2) % Nb]
            i++
        }
        state[2][Nb - 2] = temp1
        state[2][Nb - 1] = temp2
        temp1 = state[3][0]
        temp2 = state[3][1]
        temp3 = state[3][2]
        i = 0
        while (i < Nb - 3) {
            state[3][i] = state[3][(i + 3) % Nb]
            i++
        }
        state[3][Nb - 3] = temp1
        state[3][Nb - 2] = temp2
        state[3][Nb - 1] = temp3
        return state
    }
    private fun subBytes(state: Array<IntArray>): Array<IntArray>? {
        for (i in 0..3) {
            for (j in 0 until Nb) {
                state[i][j] = subWord(state[i][j]) and 0xFF
            }
        }
        return state
    }
    private fun subWord(word: Int): Int {
        var subWord = 0
        var i = 24
        while (i >= 0) {
            val `in` = word shl i ushr 24
            subWord = subWord or (AesHelper.sBox[`in`] shl 24 - i)
            i -= 8
        }
        return subWord
    }

    private fun xtime(b: Int): Int {
        return if (b and 0x80 == 0) {
            b shl 1
        } else b shl 1 xor 0x11b
    }
    private fun xor(a: ByteArray, b: ByteArray): ByteArray? {
        val result = ByteArray(Math.min(a.size, b.size))
        for (j in result.indices) {
            val xor: Byte = a[j] xor b[j]
            result[j] = (0xff and xor.toInt()).toByte()
        }
        return result
    }

    fun ECB_encrypt(text: ByteArray): ByteArray? {
        val out = ByteArrayOutputStream()
        var i = 0
        while (i < text.size) {
            try {
                out.write(encrypt(Arrays.copyOfRange(text, i, i + 16)))
            } catch (e: IOException) {
                e.printStackTrace()
            }
            i += 16
        }
        return out.toByteArray()
    }

    fun ECB_decrypt(text: ByteArray): ByteArray? {
        val out = ByteArrayOutputStream()
        var i = 0
        while (i < text.size) {
            try {
                out.write(decrypt(Arrays.copyOfRange(text, i, i + 16)))
            } catch (e: IOException) {
                e.printStackTrace()
            }
            i += 16
        }
        return out.toByteArray()
    }

    fun CBC_encrypt(text: ByteArray): ByteArray? {
        var previousBlock: ByteArray? = null
        val out = ByteArrayOutputStream()
        var i = 0
        while (i < text.size) {
            var part = Arrays.copyOfRange(text, i, i + 16)
            try {
                if (previousBlock == null) previousBlock = iv
                part = xor(previousBlock, part)
                previousBlock = encrypt(part)
                out.write(previousBlock)
            } catch (e: IOException) {
                e.printStackTrace()
            }
            i += 16
        }
        return out.toByteArray()
    }

    fun CBC_decrypt(text: ByteArray): ByteArray? {
        var previousBlock: ByteArray? = null
        val out = ByteArrayOutputStream()
        var i = 0
        while (i < text.size) {
            val part = Arrays.copyOfRange(text, i, i + 16)
            var tmp = decrypt(part)
            try {
                if (previousBlock == null) previousBlock = iv
                tmp = xor(previousBlock, tmp!!)
                previousBlock = part
                out.write(tmp)
            } catch (e: IOException) {
                e.printStackTrace()
            }
            i += 16
        }
        return out.toByteArray()
    }
}