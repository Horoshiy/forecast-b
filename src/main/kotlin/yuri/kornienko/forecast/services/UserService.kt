package yuri.kornienko.forecast.services

import org.springframework.beans.factory.annotation.Value
import org.springframework.http.HttpStatus
import org.springframework.mail.SimpleMailMessage
import org.springframework.mail.javamail.JavaMailSender
import org.springframework.security.core.context.ReactiveSecurityContextHolder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import org.springframework.util.MultiValueMap
import org.springframework.web.server.ResponseStatusException
import reactor.core.publisher.Mono
import yuri.kornienko.forecast.*
import java.time.LocalDateTime
import java.util.*

@Service
class UserService(@Value("\${support.newUserSubject}") val newUserSubject: String,
                  @Value("\${support.welcomeWithLink}") val welcomeWithLink: String,
                  @Value("\${support.passwordReminderLink}") val passwordReminderLink: String,
                  @Value("\${support.passwordReminderText}") val passwordReminderText: String,
                  val jwtUtil: JWTUtil, val mailSender: JavaMailSender, val passwordResetTokenRepository: PasswordResetTokenRepository, val repo: UserRepository, val passwordEncoder: PasswordEncoder) {
    fun byUsername(username: String): Mono<User> = repo.findByEmail(username)
    fun byUsernameAndToken(username: String, token: String): Mono<User> = repo.findByEmailAndToken(username, token)
    fun all(numbers: MultiValueMap<String, String>) =
            repo.findAll().flatMap {  toSimpleUserDto(it) }

    fun pages(numbers: MultiValueMap<String, String>) = all(numbers)
    fun byId(id: String) = repo.findById(id)
    fun byIdToDto(id: String) = byId(id).flatMap { toSimpleUserDto(it) }
    fun userDetails(): Mono<User> = ReactiveSecurityContextHolder.getContext()
            .switchIfEmpty(Mono.error(IllegalStateException("ReactiveSecurityContext empty")))
            .flatMap { repo.findByEmail(it.authentication.name) }

    fun save(item: RegisterRequest) = byUsername(item.username)
            .switchIfEmpty(Mono.just(User(email = item.username,
                    password = passwordEncoder.encode(item.password),
                    additionalInfo = item.oldName,
                    enabled = false, roles = mutableListOf(Roles.ROLE_USER),
                    name = item.fullName)).flatMap { user ->
                mailSender.send(constructEmail(newUserSubject, "$welcomeWithLink?username=${user.email}&token=${user.token}", user.email))
                repo.save(user)
            }).flatMap { toDto(it) }

    fun saveDefaultUser(item: RegisterRequest) = byUsername(item.username)
            .switchIfEmpty(Mono.just(User(email = item.username,
                    password = passwordEncoder.encode(item.password),
                    additionalInfo = item.oldName,
                    enabled = false,
                    roles = mutableListOf(Roles.ROLE_USER, Roles.ROLE_ADMIN),
                    name = item.fullName))
                    .flatMap {user ->
                        mailSender.send(constructEmail(newUserSubject, "$welcomeWithLink?username=${user.email}&token=${user.token}", user.email))
                        repo.save(user)
                    }
            ).flatMap { toDto(it) }


    fun update(item: User) = repo.save(item).flatMap { toDtoWithoutPassword(it) }

    fun delete(id: String) = repo.deleteById(id)
    fun toDtoWithoutPassword(item: User): Mono<UserWithoutPasswordDto> = Mono.just(
            UserWithoutPasswordDto(id = item.id, username = item.email, roles = item.roles, registration = item.registeredDate,
                    enabled = item.enabled, name = item.name, additionalInfo = item.additionalInfo)
    )

    fun byToken(token: String) = repo.findByToken(token)

    fun toSimpleUserDto(item: User): Mono<SimpleUserDto> = Mono.just(
            SimpleUserDto(id = item.token, name = item.name)
    )

    fun toDto(item: User): Mono<UserDto> = Mono.just(UserDto(username = item.email,
            activeTo = "", registration = item.registeredDate, name = item.name, course = item.additionalInfo))

    fun accountActivate(data: MultiValueMap<String, String>): Mono<AuthResponse> {
        val email = data.getFirst("username")
        val token = data.getFirst("token")
        return if (!email.isNullOrEmpty() && !token.isNullOrEmpty()) {
            byUsernameAndToken(email, token)
                    .filter { !it.enabled }
                    .map {
                        User(id = it.id, email = it.email, name = it.name, additionalInfo = it.additionalInfo, roles = it.roles,
                                registeredDate = it.registeredDate, enabled = true, password = it.password, token = it.token)
                    }
                    .flatMap { repo.save(it).zipWith(toDtoWithoutPassword(it)) }
                    .map { AuthResponse(token = jwtUtil.generateToken(it.t1), user = it.t2) }
                    .switchIfEmpty(Mono.error(ResponseStatusException(HttpStatus.FORBIDDEN)))
        } else {
            Mono.error(ResponseStatusException(HttpStatus.FORBIDDEN))
        }
    }

    fun token(item: AuthRequest): Mono<AuthResponse> = byUsername(item.email)
            .filter { passwordEncoder.matches(item.password, it.password) }
            .flatMap { Mono.just(jwtUtil.generateToken(it)).zipWith(toDtoWithoutPassword(it)) }
            .map { AuthResponse(token = it.t1, user = it.t2) }
            .switchIfEmpty(Mono.error(ResponseStatusException(HttpStatus.UNAUTHORIZED)))


    fun passwordRecoveryAuthorize(item: PasswordTokenRequest): Mono<Message> =
            passwordResetTokenRepository.findByCodeAndUser(item.token, item.username)
                    .filter { it.expireDate.isAfter(LocalDateTime.now()) }
                    .zipWith(byUsername(item.username))
                    .flatMap { passwordResetTokenDeleteAndUserInfoUpdating(it.t1.id, it.t2, item.password) }
                    .map { Message("Пароль изменён") }
                    .switchIfEmpty(Mono.error(ResponseStatusException(HttpStatus.NOT_FOUND)))

    private fun passwordResetTokenDeleteAndUserInfoUpdating(tokenId: String, user: User, password: String) =
            passwordUpdating(user, password)
                    .map { passwordResetTokenRepository.deleteById(tokenId).subscribe { println("token deleted") } }

    private fun passwordUpdating(user: User, newPassword: String): Mono<User> = repo.save(
            User(id = user.id, token = user.token, email = user.email, name = user.name, additionalInfo = user.additionalInfo, roles = user.roles,
                    registeredDate = user.registeredDate, enabled = user.enabled, password = passwordEncoder.encode(newPassword)))

    fun user() = userDetails().flatMap { toDtoWithoutPassword(it) }

    fun validateToken(token: Optional<String>): Mono<Boolean> = Mono.just(jwtUtil.validateToken(token.get()))

    fun sendPasswordToken(item: EmailRequest) =
            byUsername(item.username)
                    .flatMap { user ->
                        passwordResetTokenRepository.findByUser(user.email)
                                .map { passwordResetTokenRepository.delete(it).subscribe { println("token deleted") } }
                                .then(Mono.just(PasswordResetToken(user = item.username, expireDate = LocalDateTime.now().plusHours(4))))
                                .flatMap { passwordResetTokenRepository.save(it) }
                                .map { mailSender.send(constructResetTokenEmail(it)) }
                                .map { Message("username sended") }
                    }
                    .switchIfEmpty(Mono.error(ResponseStatusException(HttpStatus.NOT_FOUND)))


    fun constructEmail(subject: String, body: String, user: String): SimpleMailMessage {
        val email = SimpleMailMessage()
        email.setSubject(subject)
        email.setText(body)
        email.setTo(user)
        email.setFrom("admin@ligaonline.ru")
        return email
    }

    fun constructResetTokenEmail(prt: PasswordResetToken): SimpleMailMessage {
        val url = "$passwordReminderText?username=${prt.user}&token=${prt.code}"
        return constructEmail(passwordReminderLink, url, prt.user)
    }
}