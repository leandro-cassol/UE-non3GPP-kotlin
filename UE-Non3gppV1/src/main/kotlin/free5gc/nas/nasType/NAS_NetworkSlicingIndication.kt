package free5gc.nas.nasType

class NetworkSlicingIndication {
    var octet: UByte = 0u

    @JvmName("getIeiNetworkSlicingIndication")
    fun getIei(): UByte {
        return (octet.toInt() and getBitMask(8, 4).toInt() shr 4).toUByte()
    }

    @JvmName("setIeiNetworkSlicingIndication")
    fun setIei(iei: UByte) {
        octet = (octet.toInt() and 15 or ((iei.toInt() and 15) shl 4)).toUByte()
    }

    fun getDCNI(): UByte {
        return (octet.toInt() and getBitMask(2, 1).toInt() shr 1).toUByte()
    }

    fun setDCNI(dCNI: UByte) {
        octet = (octet.toInt() and 253 or ((dCNI.toInt() and 1) shl 1)).toUByte()
    }

    fun getNSSCI(): UByte {
        return (octet.toInt() and getBitMask(1, 0).toInt()).toUByte()
    }

    fun setNSSCI(nSSCI: UByte) {
        octet = (octet.toInt() and 254 or (nSSCI.toInt() and 1)).toUByte()
    }

    companion object {
        fun newNetworkSlicingIndication(iei: UByte): NetworkSlicingIndication {
            val networkSlicingIndication = NetworkSlicingIndication()
            networkSlicingIndication.setIei(iei)
            return networkSlicingIndication
        }

        private fun getBitMask(pos: Int, len: Int): UByte {
            return ((1 shl len) - 1 shl pos).toUByte()
        }
    }
}