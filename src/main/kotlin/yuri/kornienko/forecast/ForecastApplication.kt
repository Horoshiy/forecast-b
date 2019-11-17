package yuri.kornienko.forecast

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.annotation.Bean
import org.springframework.http.MediaType
import org.springframework.web.reactive.function.server.router
import yuri.kornienko.forecast.handlers.UserHandler

@SpringBootApplication
class ForecastApplication(userHandler: UserHandler) {
    @Bean
    fun router(userHandler: UserHandler) = router {
        accept(MediaType.APPLICATION_JSON).nest {
            "/public".nest {
                "/user".nest {
                    POST("/", userHandler::addItem)
                    POST("/auth", userHandler::auth)
                    GET("/activate", userHandler::accountActivate)
                    "/password".nest {
                        POST("/change", userHandler::getTokenAfterPasswordRecovery)
                        POST("/reset", userHandler::sendResetPasswordLink)
                    }
                }
            }
            "/private".nest {
                "/user".nest {
                    GET("/", userHandler::getUsername)
                    GET("/valid", userHandler::validateToken)
                    PUT("/", userHandler::updateOwnItem)
                }
                "/admin".nest {
                    "/user".nest {
                        GET("/", userHandler::getItems)
                        GET("/pages", userHandler::getPageNumbers)
                        GET("/{id}", userHandler::getItem)
                        PUT("/{id}", userHandler::updateItem)
                        DELETE("/{id}", userHandler::deleteItem)
                    }
                }
            }
        }
    }
}

fun main(args: Array<String>) {
    runApplication<ForecastApplication>(*args)
}
