package engine.util

import go.net.IP
import go.net.IPNet
import java.math.BigInteger
import java.net.InetAddress
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.regex.Pattern
import kotlin.experimental.and
import kotlin.experimental.xor

class Util {
    val dnsName: String = "^([a-zA-Z0-9_]{1}[a-zA-Z0-9_-]{0,62}){1}(\\.[a-zA-Z0-9_]{1}[a-zA-Z0-9_-]{0,62})*[\\._]?$"
    val rxDNSName: Pattern = Pattern.compile(dnsName)

    fun isHost(str: String): Boolean {
        return isIP(str) || isDNSName(str)
    }

    private fun isIP(str: String): Boolean {
        return InetAddress.getByName(str) != null
    }

    private fun isDNSName(str: String): Boolean {
        if (str == "" || str.replace(".", "").length > 255) {
            return false
        }
        return !isIP(str) && rxDNSName.matcher(str).matches()
    }
}

data class Quadruple<A, B, C, D>(val first: A, val second: B, val third: C, val fourth: D)

fun UShort.toBytes(): ByteArray {
    return byteArrayOf((this.toInt() shr 8).toByte(), this.toByte())
}

fun ByteArray.toShort(): Short {
    require(size >= 2) { "ByteArray must have at least 2 bytes to convert to UShort" }
    val byteBuffer = ByteBuffer.wrap(this)
    return byteBuffer.getShort()
}

fun ByteArray.toInt(): Int {
    val byteBuffer = ByteBuffer.wrap(this)
    return byteBuffer.getInt()
}


fun ByteArray.toUIntBigEndian(): UInt {
    // Garante que o array tem pelo menos 4 bytes
    if (this.size < 4) throw IllegalArgumentException("ByteArray must contain at least 4 bytes")

    return ((this[0].toUInt() and 0xFFu) shl 24) or
            ((this[1].toUInt() and 0xFFu) shl 16) or
            ((this[2].toUInt() and 0xFFu) shl 8) or
            (this[3].toUInt() and 0xFFu)
}



fun ByteArray.toHexString() = joinToString("") { "%02x".format(it) }

// Cria um ByteArray a partir de uma String.
// Exemplo: strToByteArray("255 255 255 255 10 5 2")
fun strToByteArray(textoValores: String): ByteArray {
    // Dividindo os valores e convertendo para ByteArray
    val byteArray = textoValores.split(" ").map { it.toUByte() }.toUByteArray()
    return byteArray.toByteArray()
}

fun ByteArray.removeZero(): ByteArray {
    if (this.isEmpty()) {
        return this
    }
    val aux = this.toUByteArray()
    if (aux[0].toInt() == 0) {
        return aux.copyOfRange(1, aux.size).toByteArray()
    }
    return aux.toByteArray()
}

fun ByteArray.toBigInteger(): BigInteger {
    var result = BigInteger.ZERO
    for (i in this.indices) {
        result = result shl 8
        result = result or (this[i].toInt() and 0xFF).toBigInteger()
    }
    return result
}

// Converter ByteBuffer para ByteArray
fun ByteBuffer.toByteArray(): ByteArray {
    val retornoByteArray = ByteArray(this.remaining())
    this.get(retornoByteArray)
    return retornoByteArray
}

fun hexStringToByteArray(hex: String): ByteArray {
    val len = hex.length
    val result = ByteArray(len / 2)

    for (i in 0 until len step 2) {
        result[i / 2] = ((Character.digit(hex[i], 16) shl 4) + Character.digit(hex[i + 1], 16)).toByte()
    }
    return result
}

fun generateRandomIPInRange(subnet: IPNet?): IP? {
    if (subnet == null) return null

    val ipAddr = ByteArray(4)
    val randomNumber = ByteArray(4)

    SecureRandom().nextBytes(randomNumber)

    for (i in 0..3) {
        val alter = randomNumber[i] and (subnet.mask.data[i] xor 255.toByte())
        ipAddr[i] = (subnet.ip.ipBytes[i] + alter).toByte()
    }

    return IP().iPv4(ipAddr[0], ipAddr[1], ipAddr[2], ipAddr[3])
}

fun UInt.toByteArray(): ByteArray {
    val buffer = ByteBuffer.allocate(Integer.BYTES)
    buffer.putInt(this.toInt())
    return buffer.array()
}

fun ByteArray.toUInt(): UInt {
    val buffer = ByteBuffer.wrap(this)
    return buffer.int.toUInt()
}

fun ByteArray.toUByteArrayString(): String {
    return this.toUByteArray().contentToString()
}