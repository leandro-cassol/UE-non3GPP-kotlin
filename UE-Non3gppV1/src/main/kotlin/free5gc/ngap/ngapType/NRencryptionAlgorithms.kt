package free5gc.ngap.ngapType

import free5gc.util.BitString

data class NRencryptionAlgorithms(
    val value: BitString // Assuming a BitSet can be used to represent a BitString of size 16
)
