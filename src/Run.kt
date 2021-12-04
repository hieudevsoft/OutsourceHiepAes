import AesHelper.showMenuOption
import java.util.*

fun main() {
    val sc = Scanner(System.`in`)
    var option = 1
    while (true) {
        if (option >= 1 && option <= 6) {
            showMenuOption()
        }
        try {
            option = sc.nextInt()
            sc.nextLine()
        } catch (e: Exception) {
            option = -1
            sc.nextLine()
        }
        when (option) {
            1 -> Encryption.ECBEncryptionWithKey(sc)
            2 -> Encryption.CBCEncryptionWithKey(sc)
            3 -> Encryption.ECBEncryptionWithRandomKey(sc)
            4 -> Encryption.CBCEncryptionWithRandomKey(sc)
            5 -> Encryption.diffBit()
            6 -> {}
            else -> {
                println("Vui lòng nhập đúng lựa chọn .")
                print("Chọn lại: ")
            }
        }
        println()
        if (option == 6) {
            println("BYE!")
            break
        }
    }
}
