package free5gc.nas.nasType

class IntegrityProtectionMaximumDataRate {
    var iei: UByte = 0u
    var octet = UByteArray(2)

    @JvmName("getIeiIntegrityProtectionMaximumDataRate")
    fun getIei(): UByte = iei

    @JvmName("setIeiIntegrityProtectionMaximumDataRate")
    fun setIei(iei: UByte) {
        this.iei = iei
    }

    fun getMaximumDataRatePerUEForUserPlaneIntegrityProtectionForUpLink(): UByte {
        return octet[0]
    }

    fun setMaximumDataRatePerUEForUserPlaneIntegrityProtectionForUpLink(maximumDataRatePerUEForUserPlaneIntegrityProtectionForUpLink: UByte) {
        octet[0] = maximumDataRatePerUEForUserPlaneIntegrityProtectionForUpLink
    }

    fun getMaximumDataRatePerUEForUserPlaneIntegrityProtectionForDownLink(): UByte {
        return octet[1]
    }

    fun setMaximumDataRatePerUEForUserPlaneIntegrityProtectionForDownLink(maximumDataRatePerUEForUserPlaneIntegrityProtectionForDownLink: UByte) {
        octet[1] = maximumDataRatePerUEForUserPlaneIntegrityProtectionForDownLink
    }

    companion object {
        fun newIntegrityProtectionMaximumDataRate(iei: UByte): IntegrityProtectionMaximumDataRate {
            val integrityProtectionMaximumDataRate = IntegrityProtectionMaximumDataRate()
            integrityProtectionMaximumDataRate.setIei(iei)
            return integrityProtectionMaximumDataRate
        }
    }
}