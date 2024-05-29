package free5gc.nas.nasType

class ShortNameForNetwork {
    var iei: UByte = 0u
    var len: UByte = 0u
    var buffer: UByteArray = UByteArray(0)

    @JvmName("getIeiShortNameForNetwork")
    fun getIei(): UByte = iei

    @JvmName("setIeiShortNameForNetwork")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenShortNameForNetwork")
    fun getLen(): UByte = len

    @JvmName("setLenShortNameForNetwork")
    fun setLen(len: UByte) {
        this.len = len
        buffer = UByteArray(len.toInt())
    }

    fun getExt(): UByte = (buffer[0].toInt() and getBitMask(8, 7).toInt() shr 7).toUByte()

    fun setExt(ext: UByte) {
        buffer[0] = (buffer[0].toInt() and 127 or ((ext.toInt() and 1) shl 7)).toUByte()
    }

    fun getCodingScheme(): UByte = (buffer[0].toInt() and getBitMask(7, 4).toInt() shr 4).toUByte()

    fun setCodingScheme(codingScheme: UByte) {
        buffer[0] = (buffer[0].toInt() and 143 or ((codingScheme.toInt() and 7) shl 4)).toUByte()
    }

    fun getAddCI(): UByte = (buffer[0].toInt() and getBitMask(4, 3).toInt() shr 3).toUByte()

    fun setAddCI(addCI: UByte) {
        buffer[0] = (buffer[0].toInt() and 247 or ((addCI.toInt() and 1) shl 3)).toUByte()
    }

    fun getNumberOfSpareBitsInLastOctet(): UByte = (buffer[0].toInt() and getBitMask(3, 0).toInt()).toUByte()

    fun setNumberOfSpareBitsInLastOctet(numberOfSpareBitsInLastOctet: UByte) {
        buffer[0] = (buffer[0].toInt() and 248 or (numberOfSpareBitsInLastOctet.toInt() and 7)).toUByte()
    }

    fun getTextString(): UByteArray = buffer.copyOfRange(1, buffer.size)

    fun setTextString(textString: UByteArray) {
        for (i in textString.indices) {
            if (i + 1 < buffer.size) {
                buffer[i + 1] = textString[i]
            }
        }
    }

    companion object {
        fun getBitMask(high: Int, low: Int): UByte {
            return ((1 shl (high - low + 1)) - 1 shl low).toUByte()
        }

        fun newShortNameForNetwork(iei: UByte): ShortNameForNetwork {
            val shortNameForNetwork = ShortNameForNetwork()
            shortNameForNetwork.setIei(iei)
            return shortNameForNetwork
        }
    }
}