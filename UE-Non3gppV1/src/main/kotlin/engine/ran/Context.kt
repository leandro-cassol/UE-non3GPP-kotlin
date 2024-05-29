package engine.ran

import free5gc.nas.nasMessage.RegistrationRequest.Companion.RegistrationRequestCapability5GMMType
import free5gc.nas.nasMessage.RegistrationRequest.Companion.RegistrationRequestUESecurityCapabilityType
import free5gc.nas.nasType.Capability5GMM
import free5gc.nas.security.Count
import free5gc.openapi.models.AccessType
import free5gc.openapi.models.AuthenticationSubscription
import free5gc.util.ueauth.*
import kotlin.experimental.xor

class RanUeContext {
    var supi: String = ""
    var ranUeNgapId: Long = 0
    var amfUeNgapId: Long = 0
    var ulCount: Count = Count(0u)
    var dlCount: Count = Count(0u)
    var cipheringAlg: UByte = 0u
    var integrityAlg: UByte = 0u
    var knasEnc: UByteArray = UByteArray(16)
    var knasInt: UByteArray = UByteArray(16)
    var kamf: UByteArray = UByteArray(0)
    var anType: AccessType? = null
    var authenticationSubs: AuthenticationSubscription? = null

    companion object {
        fun newRanUeContext(supi: String, ranUeNgapId: Long, cipheringAlg: UByte, integrityAlg: UByte, anType: AccessType): RanUeContext {
            val ue = RanUeContext()
            ue.ranUeNgapId = ranUeNgapId
            ue.supi = supi
            ue.cipheringAlg = cipheringAlg
            ue.integrityAlg = integrityAlg
            ue.anType = anType
            return ue
        }
    }

    private fun derivateAlgKey() {
        var p0 = byteArrayOf(free5gc.nas.security.NNASEncAlg.toByte())
        var l0 = kdfLen(p0)
        var p1 = byteArrayOf(cipheringAlg.toByte())
        var l1 = kdfLen(p1)
        val kenc = getKdfValue(kamf.toByteArray(), FC_FOR_ALGORITHM_KEY_DERIVATION, p0, l0, p1, l1)
        knasEnc = kenc.copyOfRange(16, 32).toUByteArray()

        p0 = byteArrayOf(free5gc.nas.security.NNASIntAlg.toByte())
        l0 = kdfLen(p0)
        p1 = byteArrayOf(integrityAlg.toByte())
        l1 = kdfLen(p1)
        val kint = getKdfValue(kamf.toByteArray(), FC_FOR_ALGORITHM_KEY_DERIVATION, p0, l0, p1, l1)
        knasInt = kint.copyOfRange(16, 32).toUByteArray()
    }

    fun deriveRESstarAndSetKey(authSubs: AuthenticationSubscription, rand: ByteArray, snName: String): ByteArray {
        val sqn = authSubs.sequenceNumber.hexStringToByteArray()
        val amf = authSubs.authenticationManagementField.hexStringToByteArray()

        val macA = ByteArray(8)
        val macS = ByteArray(8)
        val ck = ByteArray(16)
        val ik = ByteArray(16)
        val res = ByteArray(8)
        val ak = ByteArray(6)
        val akStar = ByteArray(6)
        var opc = ByteArray(16)
        val k = authSubs.permanentKey!!.permanentKeyValue.hexStringToByteArray()

        if (authSubs.opc!!.opcValue == "") {
            val opStr = authSubs.milenage!!.op!!.opValue
            val op = opStr.hexStringToByteArray()
            opc = free5gc.util.milenage.generateOPC(k, op)
        } else {
            opc = authSubs.opc!!.opcValue.hexStringToByteArray()
        }

        // Generate MAC_A, MAC_S
        free5gc.util.milenage.f1(opc, k, rand, sqn, amf, macA, macS)

        // Generate RES, CK, IK, AK, AKstar
        free5gc.util.milenage.f2345(opc, k, rand, res, ck, ik, ak, akStar)

        val key = ck + ik
        val fc = FC_FOR_RES_STAR_XRES_STAR_DERIVATION
        val p0 = snName.toByteArray()
        val p1 = rand
        val p2 = res
        derivateKamf(key, snName, sqn, ak)
        derivateAlgKey()
        val kdfValForResStar = getKdfValue(key, fc, p0, kdfLen(p0), p1, kdfLen(p1), p2, kdfLen(p2))
        val result = kdfValForResStar.copyOfRange(kdfValForResStar.size / 2, kdfValForResStar.size)
        return result
    }

    private fun derivateKamf(key: ByteArray, snName: String, sqn: ByteArray, ak: ByteArray) {
        val fc = FC_FOR_KAUSF_DERIVATION
        var p0 = snName.toByteArray()
        val sqnXorAK = ByteArray(6)
        for (i in sqn.indices) {
            sqnXorAK[i] = (sqn[i] xor ak[i])
        }
        var p1 = sqnXorAK
        val kausf = getKdfValue(key, fc, p0, kdfLen(p0), p1, kdfLen(p1))

        p0 = snName.toByteArray()
        val kseaf = getKdfValue(kausf, FC_FOR_KSEAF_DERIVATION, p0, kdfLen(p0))

        val supiRegexp = Regex("(?:imsi|supi)-([0-9]{5,15})")
        val groups = supiRegexp.find(supi)?.groupValues

        p0 = groups!![1].toByteArray()
        val l0 = kdfLen(p0)
        p1 = byteArrayOf(0x00, 0x00)
        val l1 = kdfLen(p1)
        kamf = getKdfValue(kseaf, FC_FOR_KAMF_DERIVATION, p0, l0, p1, l1).toUByteArray()
    }

    fun getUESecurityCapability(): free5gc.nas.nasType.UESecurityCapability {
        val ueSecurityCapability = free5gc.nas.nasType.UESecurityCapability()
        ueSecurityCapability.iei = RegistrationRequestUESecurityCapabilityType
        ueSecurityCapability.len = 2u
        ueSecurityCapability.buffer = (byteArrayOf(0x00, 0x00)).toUByteArray()
        when (cipheringAlg) {
            free5gc.nas.security.AlgCiphering128NEA0 -> ueSecurityCapability.setEA0_5G(1u)
            free5gc.nas.security.AlgCiphering128NEA1 -> ueSecurityCapability.setEA1_128_5G(1u)
            free5gc.nas.security.AlgCiphering128NEA2 -> ueSecurityCapability.setEA2_128_5G(1u)
            free5gc.nas.security.AlgCiphering128NEA3 -> ueSecurityCapability.setEA3_128_5G(1u)
        }
        when (integrityAlg) {
            free5gc.nas.security.AlgIntegrity128NIA0 -> ueSecurityCapability.setIA0_5G(1u)
            free5gc.nas.security.AlgIntegrity128NIA1 -> ueSecurityCapability.setIA1_128_5G(1u)
            free5gc.nas.security.AlgIntegrity128NIA2 -> ueSecurityCapability.setIA2_128_5G(1u)
            free5gc.nas.security.AlgIntegrity128NIA3 -> ueSecurityCapability.setIA3_128_5G(1u)
        }
        return ueSecurityCapability
    }

    fun get5GMMCapability(): Capability5GMM {
        val cap5GMM = Capability5GMM()
        cap5GMM.iei = RegistrationRequestCapability5GMMType
        cap5GMM.len = 1u
        cap5GMM.octet = ubyteArrayOf(0x07u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u)
        return cap5GMM
    }

    fun getBearerType(): Byte {
        return when (anType) {
            AccessType.AccessType__3_GPP_ACCESS -> free5gc.nas.security.Bearer3GPP.toByte()
            AccessType.AccessType_NON_3_GPP_ACCESS -> free5gc.nas.security.BearerNon3GPP.toByte()
            else -> free5gc.nas.security.OnlyOneBearer.toByte()
        }
    }

    fun getBearerByType(accessType: AccessType): Byte {
        return when (accessType) {
            AccessType.AccessType__3_GPP_ACCESS -> free5gc.nas.security.Bearer3GPP.toByte()
            AccessType.AccessType_NON_3_GPP_ACCESS -> free5gc.nas.security.BearerNon3GPP.toByte()
            else -> free5gc.nas.security.OnlyOneBearer.toByte()
        }
    }

    private fun String.hexStringToByteArray(): ByteArray {
        val len = length
        val data = ByteArray(len / 2)
        var i = 0
        while (i < len) {
            data[i / 2] = ((Character.digit(this[i], 16) shl 4) + Character.digit(this[i + 1], 16)).toByte()
            i += 2
        }
        return data
    }
}