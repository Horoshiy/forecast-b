package yuri.kornienko.forecast.handlers

import org.springframework.http.MediaType
import org.springframework.stereotype.Component
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.ServerResponse
import reactor.core.publisher.Mono
import yuri.kornienko.forecast.*
import yuri.kornienko.forecast.services.UserService

@Component
class UserHandler(private val service: UserService, private val encoder: PBKDF2Encoder) {
    fun getUsername(request: ServerRequest) = ServerResponse.ok()
            .contentType(MediaType.APPLICATION_JSON)
            .body(service.user(), UserWithoutPasswordDto::class.java)
            .switchIfEmpty(ServerResponse.noContent().build())

    fun validateToken(request: ServerRequest) = ServerResponse.ok()
            .contentType(MediaType.APPLICATION_JSON)
            .body(service.validateToken(request.queryParam("token")), Boolean::class.java)
            .switchIfEmpty(ServerResponse.noContent().build())

    fun getTokenAfterPasswordRecovery(request: ServerRequest) = request.bodyToMono(PasswordTokenRequest::class.java)
            .flatMap(::getAuthorizeToken)

    fun auth(request: ServerRequest) = request.bodyToMono(AuthRequest::class.java)
            .flatMap(::getToken)
            .switchIfEmpty(ServerResponse.badRequest().build())

    fun accountActivate(request: ServerRequest) = ServerResponse.ok()
            .contentType(MediaType.APPLICATION_JSON)
            .body(service.accountActivate(request.queryParams()), AuthResponse::class.java)
            .switchIfEmpty(ServerResponse.noContent().build())

    fun getItem(request: ServerRequest) = ServerResponse.ok()
            .contentType(MediaType.APPLICATION_JSON)
            .body(service.byIdToDto(request.pathVariable("id")), SimpleUserDto::class.java)
            .switchIfEmpty(ServerResponse.notFound().build())

    fun getItems(request: ServerRequest) = ServerResponse.ok()
            .contentType(MediaType.APPLICATION_JSON)
            .body(service.all(request.queryParams()), SimpleUserDto::class.java)
            .switchIfEmpty(ServerResponse.notFound().build())

    fun getPageNumbers(request: ServerRequest) = ServerResponse.ok()
            .contentType(MediaType.APPLICATION_JSON)
            .body(service.pages(request.queryParams()), Int::class.java)

    fun addItem(request: ServerRequest): Mono<ServerResponse> = request.bodyToMono(RegisterRequest::class.java)
            .flatMap(::saveAndRespond)

    fun sendResetPasswordLink(request: ServerRequest): Mono<ServerResponse> = request.bodyToMono(EmailRequest::class.java)
            .flatMap(::sendAndRespond)

    fun updateItem(request: ServerRequest) = request.bodyToMono(UserWithoutPassword::class.java)
            .zipWith(service.byId(request.pathVariable("id"))) { item, existingItem ->
                User(id = existingItem.id, email = existingItem.email, enabled = item.enabled, name = item.name,
                        password = existingItem.password, roles = item.roles, registeredDate = existingItem.registeredDate,
                        additionalInfo = item.additionalInfo, token = existingItem.token)
            }.flatMap(::updateAndRespond).switchIfEmpty(ServerResponse.notFound().build())

    fun updateOwnItem(request: ServerRequest) = request.bodyToMono(RegisterRequest::class.java)
            .zipWith(service.userDetails()) { item, existingItem ->
                User(id = existingItem.id, email = existingItem.email, enabled = existingItem.enabled, name = item.fullName,
                        password = encoder.encode(item.password), roles = existingItem.roles, registeredDate = existingItem.registeredDate,
                        additionalInfo = item.oldName, token = existingItem.token)
            }.flatMap(::updateAndRespond).switchIfEmpty(ServerResponse.notFound().build())

    fun deleteItem(request: ServerRequest) = ServerResponse.ok()
            .contentType(MediaType.APPLICATION_JSON)
            .body(service.delete(request.pathVariable("id")), Void::class.java)
            .switchIfEmpty(ServerResponse.notFound().build())

    private fun saveAndRespond(item: RegisterRequest) = ServerResponse.ok()
            .contentType(MediaType.APPLICATION_JSON)
            .body(service.save(item), UserDto::class.java)

    private fun sendAndRespond(item: EmailRequest) = ServerResponse.ok()
            .contentType(MediaType.APPLICATION_JSON)
            .body(service.sendPasswordToken(item), Message::class.java)

    private fun getToken(item: AuthRequest) = ServerResponse.ok()
            .contentType(MediaType.APPLICATION_JSON)
            .body(service.token(item), AuthResponse::class.java)

    private fun getAuthorizeToken(item: PasswordTokenRequest) = ServerResponse.ok()
            .contentType(MediaType.APPLICATION_JSON)
            .body(service.passwordRecoveryAuthorize(item), Message::class.java)

    private fun updateAndRespond(item: User) = ServerResponse.ok()
            .contentType(MediaType.APPLICATION_JSON)
            .body(service.update(item), UserWithoutPasswordDto::class.java)
}