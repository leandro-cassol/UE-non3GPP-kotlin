package free5gc.nas.nasType

class NegotiatedDRXParameters {
    var iei: UByte = 0u
    var len: UByte = 0u
    var octet: UByte = 0u

    @JvmName("getIeiNegotiatedDRXParameters")
    fun getIei(): UByte = iei

    @JvmName("setIeiNegotiatedDRXParameters")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenNegotiatedDRXParameters")
    fun getLen(): UByte = len

    @JvmName("setLenNegotiatedDRXParameters")
    fun setLen(len: UByte) {
        this.len = len
    }

    fun getDRXValue(): UByte {
        return octet and getBitMask(4, 0).toUByte()
    }

    fun setDRXValue(dRXValue: UByte) {
        octet = ((octet and 240u) + (dRXValue and 15u)).toUByte()
    }

    companion object {
        fun getBitMask(startPos: Int, endPos: Int): Int {
            var mask = 0
            for (i in startPos..endPos) {
                mask = mask or (1 shl i)
            }
            return mask
        }

        fun newNegotiatedDRXParameters(iei: UByte): NegotiatedDRXParameters {
            val negotiatedDRXParameters = NegotiatedDRXParameters()
            negotiatedDRXParameters.setIei(iei)
            return negotiatedDRXParameters
        }
    }
}


