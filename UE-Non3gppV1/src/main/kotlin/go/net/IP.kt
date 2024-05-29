package go.net

import go.net.util.Util

class IP {
    var ipBytes: ByteArray = ByteArray(0)

    companion object {
        const val IPv4len = 4
        const val IPv6len = 16

        fun newIP(ipBytes: ByteArray): IP {
            val ip = IP()
            ip.ipBytes = ipBytes
            return ip
        }
    }

    fun iPv4(a: Byte, b: Byte, c: Byte, d: Byte): IP {
        val p = ByteArray(IPv4len)
        p[0] = a
        p[1] = b
        p[2] = c
        p[3] = d
        return newIP(p)
    }

    fun to4(): IP? {
        if (ipBytes.size == IPv4len) {
            return this
        }
        if (ipBytes.size == IPv6len &&
            isZeros(ipBytes.copyOfRange(0, 10)) &&
            ipBytes[10] == 0xff.toByte() &&
            ipBytes[11] == 0xff.toByte()) {
            return newIP(ipBytes.copyOfRange(12, 16))
        }
        return null
    }

    private fun isZeros(p: ByteArray): Boolean {
        for (i in p.indices) {
            if (p[i] != 0.toByte()) {
                return false
            }
        }
        return true
    }


    private fun allFF(b: ByteArray): Boolean {
        for (c in b) {
            if (c != 0xff.toByte()) {
                return false
            }
        }
        return true
    }

    fun mask(mask: IPMask): IP? {
        if (mask.data.size == IPv6len && this.ipBytes.size == IPv4len && allFF(mask.data.sliceArray(0 until 12))) {
            mask.data = mask.data.sliceArray(12 until 16)
        }
        if (mask.data.size == IPv4len && this.ipBytes.size == IPv6len && Util().bytesEqual(this.ipBytes.sliceArray(0 until 12), ConstNet().v4InV6Prefix)) {
            this.ipBytes.sliceArray(12 until 16)
        }

        val n = this.ipBytes.size
        if (n != mask.data.size) {
            return null
        }
        val out = ByteArray(n)
        for (i in 0 until n) {
            out[i] = (this.ipBytes[i].toInt() and mask.data[i].toInt()).toByte()
        }
        return newIP(out)
    }


    fun string(): String {
        val p = this
        return when (p.ipBytes.size) {
            IPv4len -> {
                p.ipBytes.joinToString(".") { it.toInt().and(0xFF).toString() }
            }
            IPv6len -> {
                p.ipBytes.toList().windowed(2, 2, false) { pair ->
                    val high = pair[0].toInt().and(0xFF) shl 8
                    val low = pair[1].toInt().and(0xFF)
                    (high or low).toString(16)
                }.joinToString(":") { it }
            }
            else -> "Invalid IP Address"
        }
    }


    fun parseIPv4(s: String): IP? {
        val p = ByteArray(IPv4len)
        var i = 0
        for (j in 0 until IPv4len) {
            if (i >= s.length) {
                return null
            }
            if (j > 0) {
                if (s[i] != '.') {
                    return null
                }
                i++
            }
            val (n, c, ok) = dtoi(s)
            if (!ok || n > 0xFF) {
                return null
            }
            if (c > 1 && s[i] == '0') {
                return null
            }
            i += c
            p[j] = n.toByte()
        }
        if (i != s.length) {
            return null
        }
        return iPv4(p[0], p[1], p[2], p[3])
    }

    fun parseIPv6Zone(sParam: String): Pair<IP?, String> {
        val (s, zone) = splitHostZone(sParam)
        return Pair(parseIPv6(s), zone)
    }

    fun parseIPv6(s: String): IP? {
        val ip = ByteArray(IPv6len)
        var ellipsis = -1
        var i = 0
        if (s.length >= 2 && s[0] == ':' && s[1] == ':') {
            ellipsis = 0
            i = 2
            if (s.length == 2) {
                return newIP(ip)
            }
        }
        while (i < s.length) {
            val (n, c, ok) = xtoi(s)
            if (!ok || n > 0xFFFF) {
                return null
            }
            if (c < s.length && s[c] == '.') {
                if (ellipsis < 0 && i != IPv6len - IPv4len) {
                    return null
                }
                if (i + IPv4len > IPv6len) {
                    return null
                }
                val ip4 = parseIPv4(s.substring(i))
                if (ip4 == null) {
                    return null
                }
                ip[i] = ip4.ipBytes[12]
                ip[i + 1] = ip4.ipBytes[13]
                ip[i + 2] = ip4.ipBytes[14]
                ip[i + 3] = ip4.ipBytes[15]
                i += IPv4len
                break
            }
            ip[i] = (n shr 8).toByte()
            ip[i + 1] = n.toByte()
            i += 2
            if (i == s.length) {
                break
            }
            if (s[i] != ':') {
                return null
            }
            i++
            if (s[i] == ':') {
                if (ellipsis >= 0) {
                    return null
                }
                ellipsis = i
                i++
                if (i == s.length) {
                    break
                }
            }
        }
        if (i < IPv6len) {
            if (ellipsis < 0) {
                return null
            }
            val n = IPv6len - i
            for (j in i - 1 downTo ellipsis) {
                ip[j + n] = ip[j]
            }
            for (j in ellipsis + n - 1 downTo ellipsis) {
                ip[j] = 0
            }
        } else if (ellipsis >= 0) {
            return null
        }
        return newIP(ip)
    }

    fun parseIP(s: String): IP? {
        for (i in s.indices) {
            when (s[i]) {
                '.' -> return parseIPv4(s)
                ':' -> return parseIPv6(s)
            }
        }
        return null
    }


    fun parseCIDR(s: String): Pair<IP, IPNet>? {
        val i = s.indexOf('/')
        if (i < 0) {
            return null
        }
        val addr = s.substring(0, i)
        val mask = s.substring(i + 1)
        val ip = parseIP(addr)
        if (ip == null) {
            return null
        }
        val (n, c, ok) = dtoi(mask)
        if (ip == null || !ok || c != mask.length || n < 0 || n > 8 * ip.ipBytes.size) {
            return null
        }
        val m = cidrMask(n, 8 * ip.ipBytes.size) ?: return null
        return Pair(ip, IPNet.newIPNet(ip.mask(m)!!, m))
    }

    private fun dtoi(s: String): Triple<Int, Int, Boolean> {
        var n = 0
        var i = 0
        val big = Int.MAX_VALUE

        while (i < s.length && s[i] in '0'..'9') {
            n = n * 10 + (s[i] - '0').toInt()
            if (n >= big) {
                return Triple(big, i, false)
            }
            i++
        }

        if (i == 0) {
            return Triple(0, 0, false)
        }

        return Triple(n, i, true)
    }

    private fun xtoi(s: String): Triple<Int, Int, Boolean> {
        val big = 0xFFFFFF
        var n = 0
        var i = 0
        var ok = false

        while (i < s.length) {
            val c = s[i]
            when {
                c in '0'..'9' -> {
                    n *= 16
                    n += c - '0'
                }
                c in 'a'..'f' -> {
                    n *= 16
                    n += (c - 'a') + 10
                }
                c in 'A'..'F' -> {
                    n *= 16
                    n += (c - 'A') + 10
                }
                else -> break
            }
            if (n >= big) {
                return Triple(0, i, false)
            }
            i++
        }
        ok = i != 0
        return Triple(n, i, ok)
    }

    private fun splitHostZone(s: String): Pair<String, String> {
        val i = s.lastIndexOf('%')
        val host: String
        val zone: String

        if (i > 0) {
            host = s.substring(0, i)
            zone = s.substring(i + 1)
        } else {
            host = s
            zone = ""
        }
        return Pair(host, zone)
    }
}
