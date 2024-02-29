package sapala.s2sauthservice.api

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jws
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.io.Decoders
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import sapala.s2sauthservice.api.entity.Algorithm
import sapala.s2sauthservice.api.entity.PublicKey
import sapala.s2sauthservice.api.exceptions.ForbiddenException
import sapala.s2sauthservice.api.exceptions.UnauthorizedException
import java.security.spec.X509EncodedKeySpec
import java.time.Instant
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

@Service
class S2sTokenService(private val s2sClient: S2sClient, private val mapper: ObjectMapper) {
    companion object {
        val log: Logger = LoggerFactory.getLogger(S2sTokenService::class.java)
    }

    var s2sToken: String? = null
    private var latch: CountDownLatch? = null
    private var publicKeys: Map<String, java.security.PublicKey>? = null
    private var publicKeysLastRefresh: Long = 0
    private var publicKeysLatch: CountDownLatch? = null

    init {
        Executors.newSingleThreadScheduledExecutor()
            .scheduleAtFixedRate({ refreshPublicKeys() }, 0, 1, TimeUnit.HOURS)
    }

    fun requestToken() {
        latch = CountDownLatch(1)
        s2sClient.requestToken()
        latch!!.await(30, TimeUnit.SECONDS)
    }

    private fun refreshPublicKeys() {
        if (publicKeysLatch != null) {
            log.info("Waiting for public keys refresh")
            publicKeysLatch!!.await()
            return
        }
        log.info("Refreshing public keys")
        publicKeysLatch = CountDownLatch(1)

        val keys = s2sClient.getPublicKeys() ?: throw RuntimeException("Unable to get public keys")
        publicKeys = keys.mapValues { it.value.toKey() }

        publicKeysLastRefresh = Instant.now().epochSecond
        val latch = publicKeysLatch!!
        publicKeysLatch = null
        latch.countDown()
        log.info("Public keys refreshed")
    }

    private fun PublicKey.toKey(): java.security.PublicKey {
        val keyFactory = enumValueOf<Algorithm>(this.type).keyFactory
        val x509EncodedKeySpec = X509EncodedKeySpec(Decoders.BASE64.decode(this.publicKey))
        return keyFactory.generatePublic(x509EncodedKeySpec)
    }

    internal fun receiveToken(s2sToken: String) {
        log.info("S2S token received")
        this.s2sToken = s2sToken
        latch?.countDown()
    }

    fun validateAuthToken(authToken: String, allowedServices: Array<out String>? = null): Jws<Claims> {
        val keyId = authToken.jwtsKeyId()
        if (publicKeys == null || (!publicKeys!!.containsKey(keyId) && publicKeysLastRefresh < authToken.jwtsIssuedAt())) {
            refreshPublicKeys()
        }
        if (!publicKeys!!.containsKey(keyId)) {
            throw UnauthorizedException()
        }
        val jws = Jwts.parser()
            .verifyWith(publicKeys!![keyId])
            .build()
            .parseSignedClaims(authToken)
        if (allowedServices == null) {
            return jws
        }
        if (!allowedServices.contains(jws.payload["serviceName"])) {
            throw ForbiddenException()
        }
        return jws
    }

    private fun String.decode() = String(Decoders.BASE64.decode(this))
    private fun String.readToMap() = mapper.readValue<Map<String, String>>(this)
    private fun String.jwtsKeyId(): String = this.split(".")[0].decode().readToMap()["kid"]!!
    private fun String.jwtsIssuedAt(): Long = this.split(".")[1].decode().readToMap()["iat"]!!.toLong()
}


