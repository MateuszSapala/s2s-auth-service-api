package sapala.s2sauthservice.api

import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.responses.ApiResponse
import io.swagger.v3.oas.annotations.responses.ApiResponses
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.web.bind.annotation.*
import sapala.s2sauthservice.api.entity.TokenResponse

@RestController
@RequestMapping("/receive-token")
class S2sTokenController(private val s2sTokenService: S2sTokenService) {

    @PostMapping
    @Operation(summary = "Endpoint for receiving s2s tokens")
    @ResponseStatus(value = HttpStatus.OK)
    @ApiResponses(value = [ApiResponse(responseCode = "204", description = "Accepted")])
    fun receiveToken(@RequestBody body: TokenResponse, @RequestHeader(HttpHeaders.AUTHORIZATION) auth: String) {
        s2sTokenService.receiveToken(body.token, auth.substring(7 until auth.length))
    }
}
