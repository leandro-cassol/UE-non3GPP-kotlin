package org.example.free5gc.ngap.ngapType

class AMFRegionID(val value: ByteArray) {
    init {
        // Assegura que o tamanho do BitString seja de 8 bits (1 byte)
        require(value.size == 1) { "AMFRegionID deve ter exatamente 1 byte (8 bits)" }
    }

    // Métodos adicionais podem ser implementados conforme necessário
}