package yuri.kornienko.forecast

import org.bson.internal.Base64
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpMethod
import org.springframework.http.HttpStatus
import org.springframework.security.authentication.ReactiveAuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.context.SecurityContextImpl
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.context.ServerSecurityContextRepository
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilter
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono
import java.util.stream.Collectors
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

@Component
class PBKDF2Encoder(@Value("\${spring.security.jjwt.secret}") val secret: String,
                    @Value("\${spring.security.jjwt.iteration}") val iteration: Int,
                    @Value("\${spring.security.jjwt.keylength}") val keylength: Int) : PasswordEncoder {
    override fun encode(cs: CharSequence?): String {
        val result = SecretKeyFactory
                .getInstance("PBKDF2WithHmacSHA512")
                .generateSecret(PBEKeySpec(cs.toString().toCharArray(), secret.toByteArray(), iteration, keylength))
                .encoded
        return Base64.encode(result)
    }

    override fun matches(cs: CharSequence?, str: String?): Boolean = encode(cs) == str
}

@Component
class FieldEncryptionUtil {
    companion object {
        fun encrypt(value: String): String = Base64.encode(value.toByteArray())
        fun decrypt(value: String): String = String(Base64.decode(value))
    }
}

@Component
class AuthenticationManager(val jwtUtil: JWTUtil) : ReactiveAuthenticationManager {
    override fun authenticate(aut: Authentication?): Mono<Authentication> {
        val autToken = aut!!.credentials.toString()
        val username = jwtUtil.getUsernameFromToken(autToken)
        if (username != null && jwtUtil.validateToken(autToken)) {
            val claims = jwtUtil.getAllClaimsFromToken(autToken)
            val rolesMap: List<*>? = claims.get("role", List::class.java)
            val roles: MutableList<Roles> = mutableListOf()
            rolesMap!!.forEach { roles.add(Roles.valueOf(it.toString())) }
            return Mono.just(UsernamePasswordAuthenticationToken(username, null, roles.stream().map {
                SimpleGrantedAuthority(it.name)
            }.collect(Collectors.toList())))
        } else {
            return Mono.empty()
        }
    }
}

@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
class WebSecurityConfig(val authenticationManager: AuthenticationManager, val securityContextRepository: ServerSecurityContextRepository) {

    @Bean
    fun securityWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain =
            http.cors().and().csrf().disable()
                    .authenticationManager(authenticationManager)
                    .securityContextRepository(securityContextRepository)
                    .authorizeExchange()
                    .pathMatchers(HttpMethod.OPTIONS).permitAll()
                    .pathMatchers("/public/**").permitAll()
                    .pathMatchers("/private/admin/**").hasRole("ADMIN")
                    .pathMatchers("/private/editor/**").hasRole("EDITOR")
                    .anyExchange().authenticated()
                    .and().build()
}

@Component
class SecurityContextRepository(val authenticationManager: AuthenticationManager) : ServerSecurityContextRepository {
    override fun save(p0: ServerWebExchange?, p1: SecurityContext?): Mono<Void> {
        throw UnsupportedOperationException("Not supported yet.")
    }

    override fun load(swe: ServerWebExchange?): Mono<SecurityContext> {
        val authHeader = swe!!.request.headers.getFirst(HttpHeaders.AUTHORIZATION)
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            val authToken = authHeader.substring(7)
            val authentication: Authentication = UsernamePasswordAuthenticationToken(authToken, authToken)
            return this.authenticationManager.authenticate(authentication).map { SecurityContextImpl(it) }
        } else {
            return Mono.empty()
        }
    }
}

@Component
class CorsFilter : WebFilter {
    override fun filter(ctx: ServerWebExchange, chain: WebFilterChain): Mono<Void> {
        return if (ctx != null) {
            ctx.response.headers.add("Access-Control-Allow-Origin", "*")
            ctx.response.headers.add("Access-Control-Allow-Methods", "GET, PUT, POST, DELETE, OPTIONS")
            ctx.response.headers.add("Access-Control-Allow-Headers", "Access-Control-Allow-Origin,Authorization,DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Content-Range,Range")
            if (ctx.request.method == HttpMethod.OPTIONS) {
                ctx.response.headers.add("Access-Control-Max-Age", "1728000")
                ctx.response.statusCode = HttpStatus.NO_CONTENT
                Mono.empty()
            } else {
                ctx.response.headers.add("Access-Control-Expose-Headers", "Access-Control-Allow-Origin,DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Content-Range,Range")
                chain?.filter(ctx) ?: Mono.empty()
            }
        } else {
            chain?.filter(ctx) ?: Mono.empty()
        }
    }
}