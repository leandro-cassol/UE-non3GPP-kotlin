package free5gc.nas.nasType

class NoncurrentNativeNASKeySetIdentifier {
    var octet: UByte = 0u

    @JvmName("getIeiNoncurrentNativeNASKeySetIdentifier")
    fun getIei(): UByte {
        return (octet.toInt() and getBitMask(8, 4).toInt() shr 4).toUByte()
    }

    @JvmName("setIeiNoncurrentNativeNASKeySetIdentifier")
    fun setIei(iei: UByte) {
        octet = (octet.toInt() and 15 or ((iei.toInt() and 15) shl 4)).toUByte()
    }

    fun getTsc(): UByte {
        return (octet.toInt() and getBitMask(4, 3).toInt() shr 3).toUByte()
    }

    fun setTsc(tsc: UByte) {
        octet = (octet.toInt() and 247 or ((tsc.toInt() and 1) shl 3)).toUByte()
    }

    fun getNasKeySetIdentifiler(): UByte {
        return (octet.toInt() and getBitMask(3, 0).toInt()).toUByte()
    }

    fun setNasKeySetIdentifiler(nasKeySetIdentifiler: UByte) {
        octet = (octet.toInt() and 248 or (nasKeySetIdentifiler.toInt() and 7)).toUByte()
    }

    companion object {
        fun newNoncurrentNativeNASKeySetIdentifier(iei: UByte): NoncurrentNativeNASKeySetIdentifier {
            val noncurrentNativeNASKeySetIdentifier = NoncurrentNativeNASKeySetIdentifier()
            noncurrentNativeNASKeySetIdentifier.setIei(iei)
            return noncurrentNativeNASKeySetIdentifier
        }

        private fun getBitMask(startPos: Int, endPos: Int): UByte {
            var mask = 0
            for (i in startPos downTo endPos + 1) {
                mask = mask or (1 shl i)
            }
            return mask.toUByte()
        }
    }
}