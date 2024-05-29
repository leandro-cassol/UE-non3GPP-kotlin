package engine.util

fun strReverse(s: String): String {
    var aux = ""
    for (valor in s) {
        aux = valor.toString() + aux
    }
    return aux
}

fun strConverter(value: UInt): String {
    return value.toString()
}


