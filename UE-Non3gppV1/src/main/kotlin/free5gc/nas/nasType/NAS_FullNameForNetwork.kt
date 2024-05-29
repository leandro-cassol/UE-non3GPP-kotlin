package free5gc.nas.nasType

class FullNameForNetwork {
    var iei: UByte = 0u
    var len: UByte = 0u
    var buffer: UByteArray = UByteArray(0)

    @JvmName("getIeiFullNameForNetwork")
    fun getIei(): UByte = iei

    @JvmName("setIeiFullNameForNetwork")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenFullNameForNetwork")
    fun getLen(): UByte = len

    @JvmName("setLenFullNameForNetwork")
    fun setLen(len: UByte) {
        this.len = len
        buffer = UByteArray(len.toInt())
    }

/*
    fun getExt(): UByte = (buffer[0] and getBitMask(8u, 7u).toUByte()) shr 7

    fun setExt(ext: UByte) {
        buffer[0] = (buffer[0] and 127u.toUByte()) or ((ext and 1u) shl 7)
    }

    fun getCodingScheme(): UByte = (buffer[0] and getBitMask(7u, 4u).toUByte()) shr 4

    fun setCodingScheme(codingScheme: UByte) {
        buffer[0] = (buffer[0] and 143u.toUByte()) or ((codingScheme and 7u) shl 4)
    }

    fun getAddCI(): UByte = (buffer[0] and getBitMask(4u, 3u).toUByte()) shr 3

    fun setAddCI(addCI: UByte) {
        buffer[0] = (buffer[0] and 247u.toUByte()) or ((addCI and 1u) shl 3)
    }
*/
    fun getNumberOfSpareBitsInLastOctet(): UByte = buffer[0] and getBitMask(3u, 0u).toUByte()

    fun setNumberOfSpareBitsInLastOctet(numberOfSpareBitsInLastOctet: UByte) {
        buffer[0] = (buffer[0] and 248u.toUByte()) or (numberOfSpareBitsInLastOctet and 7u)
    }

    @JvmName("getTextStringFullNameForNetwork")
    fun getTextString(): UByteArray = buffer.copyOfRange(1, buffer.size)

    @JvmName("setTextStringFullNameForNetwork")
    fun setTextString(textString: UByteArray) {
        for (i in textString.indices) {
            buffer[i + 1] = textString[i]
        }
    }

    companion object {
        fun newFullNameForNetwork(iei: UByte): FullNameForNetwork {
            val fullNameForNetwork = FullNameForNetwork()
            fullNameForNetwork.setIei(iei)
            return fullNameForNetwork
        }

        fun getBitMask(from: UByte, to: UByte): UInt {
            var mask = 0u
            for (i in from.toInt() downTo to.toInt()) {
                mask = mask or (1u shl i)
            }
            return mask
        }
    }
}