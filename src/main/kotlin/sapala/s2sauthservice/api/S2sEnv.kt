package sapala.s2sauthservice.api

import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Configuration
import java.net.URI
import java.net.URL

@Configuration
class S2sEnv {
    @Value("\${s2s.service.url}")
    private val serviceUrl: String? = null
    fun receiveTokenUrl(): URL = URI(serviceUrl!! + "/receive-token").toURL()

    @Value("\${s2s.service.name}")
    private val serviceName: String? = null
    fun serviceName() = serviceName!!

    @Value("\${s2s.server.url}")
    private val serverUrl: String? = null
    fun serverUrlPublicKeys(): URL = URI(serverUrl!! + "/api/v1/public-keys").toURL()
    fun serverUrlRequestToken(): URL = URI(serverUrl!! + "/api/v1/request-token").toURL()
}
