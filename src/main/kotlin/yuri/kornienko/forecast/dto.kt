package yuri.kornienko.forecast

import java.time.LocalDateTime

data class AuthRequest(val email: String, val password: String)
data class AuthResponse(val token: String, val user: UserWithoutPasswordDto)
data class SimpleUserDto(val id: String, val name: String)
data class UserWithoutPasswordDto(val id: String, val username: String, val name: String, val roles: List<Roles>,
                                  val registration: LocalDateTime, val enabled: Boolean, val additionalInfo: String)

data class RegisterRequest(val username: String, val password: String, val oldName: String, val fullName: String, val repeatPassword: String?)
data class UserDto(val username: String, val name: String, val course: String, val activeTo: String, val registration: LocalDateTime)
data class PasswordTokenRequest(val token: Int, val password: String, val username: String)
data class Message(val message: String)
data class EmailRequest(val username: String)
data class UserWithoutPassword(val id: String,
                               val email: String,
                               val name: String,
                               val additionalInfo: String,
                               val roles: List<Roles>,
                               val registeredDate: LocalDateTime,
                               val enabled: Boolean)
