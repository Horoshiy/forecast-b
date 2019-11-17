package yuri.kornienko.forecast

import org.springframework.data.mongodb.repository.ReactiveMongoRepository
import reactor.core.publisher.Mono

interface UserRepository : ReactiveMongoRepository<User, String> {
    fun findByEmail(email: String): Mono<User>
    fun findByEmailAndToken(email: String, token: String): Mono<User>
    fun findByToken(token: String): Mono<User>
}

interface PasswordResetTokenRepository : ReactiveMongoRepository<PasswordResetToken, String> {
    fun findByCodeAndUser(code: Int, user: String): Mono<PasswordResetToken>
    fun findByUser(user: String): Mono<PasswordResetToken>
}