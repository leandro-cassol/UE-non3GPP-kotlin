package free5gc.nas.nasType

class NetworkFeatureSupport5GS {
    var iei: UByte = 0u
    var len: UByte = 0u
    var octet = UByteArray(3)

    @JvmName("getIeiNetworkFeatureSupport5GS")
    fun getIei(): UByte = iei

    @JvmName("setIeiNetworkFeatureSupport5GS")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    @JvmName("getLenNetworkFeatureSupport5GS")
    fun getLen(): UByte = len

    @JvmName("setLenNetworkFeatureSupport5GS")
    fun setLen(len: UByte) {
        this.len = len
    }


    /*
    fun getMPSI(): UByte = (octet[0] and getBitMask(8, 7).toUByte()) shr 7

    fun setMPSI(mPSI: UByte) {
        octet[0] = (octet[0] and 127u) or ((mPSI and 1u) shl 7)
    }

    fun getIWKN26(): UByte = (octet[0] and getBitMask(7, 6).toUByte()) shr 6

    fun setIWKN26(iWKN26: UByte) {
        octet[0] = (octet[0] and 191u) or ((iWKN26 and 1u) shl 6)
    }

    fun getEMF(): UByte = (octet[0] and getBitMask(6, 4).toUByte()) shr 4

    fun setEMF(eMF: UByte) {
        octet[0] = (octet[0] and 207u) or ((eMF and 3u) shl 4)
    }

    fun getEMC(): UByte = (octet[0] and getBitMask(4, 2).toUByte()) shr 2

    fun setEMC(eMC: UByte) {
        octet[0] = (octet[0] and 243u) or ((eMC and 3u) shl 2)
    }

    fun getIMSVoPSN3GPP(): UByte = (octet[0] and getBitMask(2, 1).toUByte()) shr 1

    fun setIMSVoPSN3GPP(iMSVoPSN3GPP: UByte) {
        octet[0] = (octet[0] and 253u) or ((iMSVoPSN3GPP and 1u) shl 1)
    }
*/
    fun getIMSVoPS3GPP(): UByte = octet[0] and getBitMask(1, 0).toUByte()

    fun setIMSVoPS3GPP(iMSVoPS3GPP: UByte) {
        octet[0] = (octet[0] and 254u) or (iMSVoPS3GPP and 1u)
    }

//    fun getMCSI(): UByte = (octet[1] and getBitMask(2, 1).toUByte()) shr 1
//
//    fun setMCSI(mCSI: UByte) {
//        octet[1] = (octet[1] and 253u) or ((mCSI and 1u) shl 1)
//    }

    fun getEMCN(): UByte = octet[1] and getBitMask(1, 0).toUByte()

    fun setEMCN(eMCN: UByte) {
        octet[1] = (octet[1] and 254u) or (eMCN and 1u)
    }

    fun getSpare(): UByte = octet[2]

    fun setSpare(spare: UByte) {
        octet[2] = spare
    }

    companion object {
        fun getBitMask(from: Int, to: Int): Int {
            var mask = 0
            for (i in from downTo to) {
                mask = mask or (1 shl i)
            }
            return mask
        }

        fun newNetworkFeatureSupport5GS(iei: UByte): NetworkFeatureSupport5GS {
            val networkFeatureSupport5GS = NetworkFeatureSupport5GS()
            networkFeatureSupport5GS.setIei(iei)
            return networkFeatureSupport5GS
        }
    }
}