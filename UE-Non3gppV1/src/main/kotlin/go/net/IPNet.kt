package go.net

class IPNet {
    var ip: IP = IP()
    var mask: IPMask = IPMask()

    companion object {
        const val IPv4len = 4
        const val IPv6len = 16

        fun newIPNet(ip: IP, mask: IPMask): IPNet {
            val iPNet = IPNet()
            iPNet.ip = ip
            iPNet.mask = mask
            return iPNet
        }
    }

    private fun networkNumberAndMask(ipNet: IPNet): Pair<IP, IPMask>? {
        val ip = ipNet.ip.to4() ?: return null
        var mask = ipNet.mask
        when (mask.data.size) {
            IPv4len -> {
                if (ip.ipBytes.size != IPv4len) {
                    return null
                }
            }
            IPv6len -> {
                if (ip.ipBytes.size == IPv4len) {
                    mask = IPMask.newIPMask(mask.data.sliceArray(12 until 16))
                }
            }
            else -> return null
        }
        return Pair(ip, mask)
    }


    fun contains(ip: IP): Boolean {
        val (nn, m) = networkNumberAndMask(this) ?: return false
        val x = ip.to4()
        val l = ip.ipBytes.size
        if (l != nn.ipBytes.size) {
            return false
        }
        for (i in 0 until l) {
            if (nn.ipBytes[i].toInt() and m.data[i].toInt() != ip.ipBytes[i].toInt() and m.data[i].toInt()) {
                return false
            }
        }
        return true
    }


    fun string(): String {
        if (this == null) {
            return "<nil>"
        }
        val (nn, m) = networkNumberAndMask(this) ?: return "<nil>"
        val l = simpleMaskLength(m)
        return if (l == -1) {
            nn.string() + "/" + m.string()
        } else {
            nn.string() + "/" + l.toString()
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
}
