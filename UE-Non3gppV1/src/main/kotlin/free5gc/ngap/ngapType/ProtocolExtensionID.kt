package org.example.free5gc.ngap.ngapType

class ProtocolExtensionID(val value: Int) {
    init {
        require(value in 0..65535) { "O valor deve estar entre 0 e 65535" }
    }

    // Métodos adicionais podem ser implementados conforme necessário
}
