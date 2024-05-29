package go.net

import go.net.util.Util

class  IPMask{
    var data: ByteArray = ByteArray(0)

    companion object {
        fun newIPMask(data: ByteArray): IPMask {
            val ipMask = IPMask()
            ipMask.data = data
            return ipMask
        }
    }

    fun iPv4Mask(a: Byte, b: Byte, c: Byte, d: Byte): IPMask {
        val p = ByteArray(IP.IPv4len)
        p[0] = a
        p[1] = b
        p[2] = c
        p[3] = d
        return newIPMask(p)
    }

    fun size(): Pair<Int, Int> {
        val ones = simpleMaskLength(this)
        val bits = this.data.size * 8
        return if (ones == -1) {
            Pair(0, 0)
        } else {
            Pair(ones, bits)
        }
    }

    private fun simpleMaskLength(mask: IPMask): Int {
        var n = 0
        for ((i, v) in mask.data.withIndex()) {
            if (v == 0xff.toByte()) {
                n += 8
                continue
            }

            // found non-ff byte
            // count 1 bits
            var tempV = v.toInt() and 0xFF
            while (tempV and 0x80 != 0) {
                n++
                tempV = tempV shl 1 and 0xFF
            }
            // rest must be 0 bits
            if (tempV != 0) {
                return -1
            }

            for (j in i + 1 until mask.data.size) {
                if (mask.data[j] != 0.toByte()) {
                    return -1
                }
            }
            break
        }
        return n
    }

    fun string(): String {
        if (this.data.isEmpty()) {
            return "<nil>"
        }
        return Util().hexString(this.data)
    }
}

fun cidrMask(ones: Int, bits: Int): IPMask? {
    if (bits != 8 * IP.IPv4len && bits != 8 * IP.IPv6len) {
        return null
    }
    if (ones < 0 || ones > bits) {
        return null
    }
    val l = bits / 8
    val m = ByteArray(l)
    var n = ones.toUInt()
    for (i in 0 until l) {
        if (n >= 8u) {
            m[i] = 0xff.toByte()
            n -= 8u
            continue
        }
        m[i] = (0xff.toUInt() shr n.toInt()).inv().toByte()
        n = 0u
    }
    return IPMask()//.newIPMask(m)
}
