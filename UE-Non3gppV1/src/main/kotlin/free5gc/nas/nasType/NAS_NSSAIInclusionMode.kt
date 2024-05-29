package free5gc.nas.nasType

class NSSAIInclusionMode {
    var octet: UByte = 0u

    @JvmName("getIeiNSSAIInclusionMode")
    fun getIei(): UByte {
        return (octet.toInt() and getBitMask(8, 4).toInt() shr 4).toUByte()
    }

    @JvmName("setIeiNSSAIInclusionMode")
    fun setIei(iei: UByte) {
        octet = (octet.toInt() and 15 or ((iei.toInt() and 15) shl 4)).toUByte()
    }

    fun getNSSAIInclusionMode(): UByte {
        return (octet.toInt() and getBitMask(2, 0).toInt()).toUByte()
    }

    fun setNSSAIInclusionMode(nSSAIInclusionMode: UByte) {
        octet = (octet.toInt() and 252 or (nSSAIInclusionMode.toInt() and 3)).toUByte()
    }

    companion object {
        fun newNSSAIInclusionMode(iei: UByte): NSSAIInclusionMode {
            val nSSAIInclusionMode = NSSAIInclusionMode()
            nSSAIInclusionMode.setIei(iei)
            return nSSAIInclusionMode
        }

        fun getBitMask(length: Int, position: Int): UByte {
            return ((1 shl length) - 1 shl position).toUByte()
        }
    }
}