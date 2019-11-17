package yuri.kornienko.forecast

import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.security.Keys
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import java.io.Serializable
import java.util.*
import javax.crypto.SecretKey
import kotlin.collections.HashMap

class RandomString {
    companion object {
        fun getNumericString(min: Int, max: Int): Int {
            return (Math.floor(Math.random() * (max - min)) + min).toInt()
        }
    }
}

class Translit {
    companion object {
        fun cyr2lat(ch: Char): String {
            when (ch) {
                'а' -> return "a"
                'б' -> return "b"
                'в' -> return "v"
                'г' -> return "g"
                'д' -> return "d"
                'е' -> return "je"
                'ё' -> return "yo"
                'ж' -> return "zh"
                'з' -> return "z"
                'и' -> return "i"
                'й' -> return "j"
                'к' -> return "k"
                'л' -> return "l"
                'м' -> return "m"
                'н' -> return "n"
                'о' -> return "o"
                'п' -> return "p"
                'р' -> return "r"
                'с' -> return "s"
                'т' -> return "t"
                'у' -> return "u"
                'ф' -> return "f"
                'х' -> return "h"
                'ц' -> return "c"
                'ч' -> return "ch"
                'ш' -> return "sh"
                'щ' -> return "sch"
                'ъ' -> return ""
                'ы' -> return "y"
                'ь' -> return ""
                'э' -> return "e"
                'ю' -> return "yu"
                'я' -> return "ya"
                ' ' -> return "_"
                '-' -> return "-"
                '_' -> return "_"
                '0' -> return "0"
                '1' -> return "1"
                '2' -> return "2"
                '3' -> return "3"
                '4' -> return "4"
                '5' -> return "5"
                '6' -> return "6"
                '7' -> return "7"
                '8' -> return "8"
                '9' -> return "9"
                'a' -> return "a"
                'b' -> return "b"
                'c' -> return "c"
                'd' -> return "d"
                'e' -> return "e"
                'f' -> return "f"
                'g' -> return "g"
                'h' -> return "h"
                'i' -> return "i"
                'j' -> return "j"
                'k' -> return "k"
                'l' -> return "l"
                'm' -> return "m"
                'n' -> return "n"
                'o' -> return "o"
                'p' -> return "p"
                'q' -> return "q"
                'r' -> return "r"
                's' -> return "s"
                't' -> return "t"
                'u' -> return "u"
                'v' -> return "v"
                'w' -> return "w"
                'x' -> return "x"
                'y' -> return "y"
                'z' -> return "z"
                else -> return ""
            }
        }

        fun cyr2lat(s: String): String {
            val sb = StringBuilder(s.length * 2)
            s.toLowerCase().toCharArray()
                    .asSequence()
                    .forEach { sb.append(cyr2lat(it)) }
            return sb.toString()
        }
    }
}

@Component
class JWTUtil(@Value("\${spring.security.jjwt.secret}") val secret: String,
              @Value("\${spring.security.jjwt.expiration}") val expirationTime: String) : Serializable {
    private val serialVersionUID: Long = 1L
    private var key: SecretKey = Keys.hmacShaKeyFor(secret.toByteArray())

    fun getAllClaimsFromToken(token: String): Claims = Jwts.parser().setSigningKey(key).parseClaimsJws(token).body

    fun getUsernameFromToken(token: String): String = getAllClaimsFromToken(token).subject

    fun getExpirationDateFromToken(token: String): Date = getAllClaimsFromToken(token).expiration

    fun isTokenExpired(token: String): Boolean = getExpirationDateFromToken(token).before(Date())

    fun generateToken(user: User): String {
        val claims = HashMap<String, Any>()
        claims["name"] = user.name
        claims["username"] = user.additionalInfo
        claims["role"] = user.roles
        claims["enable"] = user.enabled
        return doGenerateToken(claims, user.email)
    }

    fun doGenerateToken(claims: Map<String, Any>, username: String): String {
        val createdDate = Date()
        val expirationDate = Date(createdDate.time + expirationTime.toLong() * 100000)
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(createdDate)
                .setExpiration(expirationDate)
                .signWith(key, SignatureAlgorithm.HS512)
                .compact()
    }

    fun validateToken(token: String): Boolean = !isTokenExpired(token)
}