package sapala.s2sauthservice.api

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import okhttp3.MediaType
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import sapala.s2sauthservice.api.entity.PublicKey
import sapala.s2sauthservice.api.entity.RequestToken

@Service
class S2sClient(
    private val client: OkHttpClient,
    private val mapper: ObjectMapper,
    private val s2sEnv: S2sEnv,
) {
    companion object {
        private val JSON: MediaType = "application/json; charset=utf-8".toMediaType()
        private val log = LoggerFactory.getLogger(S2sClient::class.java)
    }

    internal fun getPublicKeys(): Map<String, PublicKey>? {
        val request = Request.Builder()
            .url(s2sEnv.serverUrlPublicKeys())
            .get()
            .build()
        val call = client.newCall(request)

        val response = call.execute()
        if (!response.isSuccessful) {
            log.warn("Unable to get public keys. Response {}: {}", response.code, response.body)
            return null
        }
        log.info("Successfully received public keys")
        return mapper.readValue<Map<String, PublicKey>>(response.body!!.string())
    }

    internal fun requestToken(): Boolean {
        val requestToken = RequestToken(s2sEnv.serviceName(), s2sEnv.receiveTokenUrl())
        val body = mapper.writeValueAsString(requestToken).toRequestBody(JSON)
        val request = Request.Builder()
            .url(s2sEnv.serverUrlRequestToken())
            .post(body)
            .build()
        val call = client.newCall(request)

        val response = call.execute()
        if (!response.isSuccessful) {
            log.warn("Unable to request token. Response {}: {}", response.code, response.body?.string())
            return false
        }
        log.info("Successfully requested token")
        return true
    }
}
