package sapala.s2sauthservice.api.entity

import java.net.URL

data class RequestToken(
    val serviceName: String,
    val tokenReceiverUrl: URL
)
