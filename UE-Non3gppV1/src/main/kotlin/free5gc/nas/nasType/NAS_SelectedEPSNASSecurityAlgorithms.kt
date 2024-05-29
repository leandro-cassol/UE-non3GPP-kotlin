package free5gc.nas.nasType

class SelectedEPSNASSecurityAlgorithms {
    var iei: UByte = 0u
    var octet: UByte = 0u

    @JvmName("getIeiSelectedEPSNASSecurityAlgorithms")
    fun getIei(): UByte = iei

    @JvmName("setIeiSelectedEPSNASSecurityAlgorithms")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    fun getTypeOfCipheringAlgorithm(): UByte {
        return (octet.toInt() and getBitMask(7, 4).toInt() shr 4).toUByte()
    }

    fun setTypeOfCipheringAlgorithm(typeOfCipheringAlgorithm: UByte) {
        octet = (octet.toInt() and 143 or ((typeOfCipheringAlgorithm.toInt() and 7) shl 4)).toUByte()
    }

    fun getTypeOfIntegrityProtectionAlgorithm(): UByte {
        return (octet.toInt() and getBitMask(3, 0).toInt()).toUByte()
    }

    fun setTypeOfIntegrityProtectionAlgorithm(typeOfIntegrityProtectionAlgorithm: UByte) {
        octet = (octet.toInt() and 248 or (typeOfIntegrityProtectionAlgorithm.toInt() and 7)).toUByte()
    }

    companion object {
        fun getBitMask(high: Int, low: Int): UByte {
            return ((1 shl (high + 1)) - 1 xor ((1 shl low) - 1)).toUByte()
        }

        fun newSelectedEPSNASSecurityAlgorithms(iei: UByte): SelectedEPSNASSecurityAlgorithms {
            val selectedEPSNASSecurityAlgorithms = SelectedEPSNASSecurityAlgorithms()
            selectedEPSNASSecurityAlgorithms.setIei(iei)
            return selectedEPSNASSecurityAlgorithms
        }
    }
}
