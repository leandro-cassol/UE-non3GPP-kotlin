package go.net.util

class Util {

    val hexDigit = "0123456789abcdef"

    fun bytesEqual(a: ByteArray, b: ByteArray): Boolean {
        return a.contentEquals(b)
    }

    fun hexString(b: ByteArray): String {
        val s = StringBuilder(b.size * 2)
        for (tn in b) {
            s.append(hexDigit.toCharArray()[tn.toInt() shr 4])
            s.append(hexDigit.toCharArray()[tn.toInt() and 0xf])
        }
        return s.toString()
    }
}