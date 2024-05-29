package free5gc.ngap.ngapType

import kotlinx.serialization.Serializable
import kotlinx.serialization.KSerializer
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor

@Serializable(with = CancelAllWarningMessages.Companion::class)
data class CancelAllWarningMessages(val value: Int) {
    companion object : KSerializer<CancelAllWarningMessages> {
        const val CancelAllWarningMessagesPresentTrue = 0

        override val descriptor: SerialDescriptor =
            PrimitiveSerialDescriptor("CancelAllWarningMessages", PrimitiveKind.INT)

        override fun serialize(encoder: Encoder, value: CancelAllWarningMessages) {
            encoder.encodeInt(value.value)
        }

        override fun deserialize(decoder: Decoder): CancelAllWarningMessages {
            return CancelAllWarningMessages(decoder.decodeInt())
        }
    }
}