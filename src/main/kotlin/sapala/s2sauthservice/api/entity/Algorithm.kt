package sapala.s2sauthservice.api.entity

import java.security.KeyFactory


enum class Algorithm(string: String, val keyFactory: KeyFactory) {
    RS256("RS256", KeyFactory.getInstance("RSA")),
    RS384("RS384", KeyFactory.getInstance("RSA")),
    RS512("RS512", KeyFactory.getInstance("RSA")),
    PS256("PS256", KeyFactory.getInstance("RSASSA-PSS")),
    PS384("PS384", KeyFactory.getInstance("RSASSA-PSS")),
    PS512("PS512", KeyFactory.getInstance("RSASSA-PSS")),
    ES256("ES256", KeyFactory.getInstance("EC")),
    ES384("ES384", KeyFactory.getInstance("EC")),
    ES512("ES512", KeyFactory.getInstance("EC")),
    EdDSA("EdDSA", KeyFactory.getInstance("EdDSA"))
}
