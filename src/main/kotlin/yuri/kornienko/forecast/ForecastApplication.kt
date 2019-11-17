package yuri.kornienko.forecast

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class ForecastApplication

fun main(args: Array<String>) {
	runApplication<ForecastApplication>(*args)
}
