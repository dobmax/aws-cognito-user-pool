package org.dobmax.user.pool

import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Service
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient
import software.amazon.awssdk.services.cognitoidentityprovider.model.AttributeType
import software.amazon.awssdk.services.cognitoidentityprovider.model.AttributeType.builder
import software.amazon.awssdk.services.cognitoidentityprovider.model.CognitoIdentityProviderException
import software.amazon.awssdk.services.cognitoidentityprovider.model.SignUpRequest
import java.nio.charset.StandardCharsets
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.system.exitProcess

const val HMAC_SHA256_ALGORITHM = "HmacSHA256"

@Service
class UserPoolService(
    private val identityProviderClient: CognitoIdentityProviderClient,
    @Value("\${aws.user-pool.client-id}") val clientId: String,
    @Value("\${aws.user-pool.client-secret}") val clientSecret: String,
) {
    private val log = LoggerFactory.getLogger(this::class.java)

    fun signUp(newUser: SignUpRequestDto) {
        try {
            val req =
                SignUpRequest.builder()
                    .userAttributes(newUser.mapToAttributes())
                    .username(newUser.email)
                    .password(newUser.password)
                    .clientId(clientId)
                    .secretHash(newUser.calculateSecretHash())
                    .build()

            identityProviderClient.signUp(req)
            log.info("User has been signed up ")
            exitProcess(1)
        } catch (ex: CognitoIdentityProviderException) {
            log.info("Error happened", ex)
            log.info("Details: {}", ex.awsErrorDetails())
            exitProcess(-1)
        }
    }

    private fun SignUpRequestDto.mapToAttributes(): List<AttributeType> =
        listOf(
            builder()
                .name("email")
                .value(email)
                .build(),
            builder()
                .name("given_name")
                .value(firstName)
                .build(),
            builder()
                .name("family_name")
                .value(familyName)
                .build(),
        )

    @Suppress("TooGenericExceptionCaught", "TooGenericExceptionThrown", "SwallowedException")
    private fun SignUpRequestDto.calculateSecretHash(): String {
        val signingKey =
            SecretKeySpec(
                clientSecret.toByteArray(StandardCharsets.UTF_8),
                HMAC_SHA256_ALGORITHM,
            )
        try {
            val mac = Mac.getInstance(HMAC_SHA256_ALGORITHM)
            mac.init(signingKey)
            mac.update(email.toByteArray(StandardCharsets.UTF_8))
            val rawHmac = mac.doFinal(clientId.toByteArray(StandardCharsets.UTF_8))
            return Base64.getEncoder().encodeToString(rawHmac)
        } catch (e: Exception) {
            throw RuntimeException("Error while calculating ")
        }
    }
}
