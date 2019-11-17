package yuri.kornienko.forecast

import org.springframework.data.annotation.Id
import org.springframework.data.mongodb.core.mapping.Document
import java.time.LocalDateTime
import java.util.*

@Document
data class User(@Id val id: String = UUID.randomUUID().toString(),
                val email: String,
                val name: String = "",
                val additionalInfo: String = "",
                val roles: List<Roles>,
                val registeredDate: LocalDateTime = LocalDateTime.now(),
                val token: String = UUID.randomUUID().toString(),
                val enabled: Boolean,
                val password: String)

@Document
data class PasswordResetToken(
        @Id val id: String = UUID.randomUUID().toString(),
        val user: String,
        val expireDate: LocalDateTime,
        val code: Int = RandomString.getNumericString(1000, 9999))


enum class Roles {
    ROLE_ADMIN,
    ROLE_USER,
    ROLE_EDITOR
}