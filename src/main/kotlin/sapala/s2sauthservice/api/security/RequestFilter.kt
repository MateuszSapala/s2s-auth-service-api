package sapala.s2sauthservice.api.security

import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jws
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.context.ApplicationContext
import org.springframework.http.HttpHeaders
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import org.springframework.web.method.HandlerMethod
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping
import sapala.s2sauthservice.api.S2sTokenService
import sapala.s2sauthservice.api.exceptions.ForbiddenException

@Component
class RequestFilter(
    private val jwtService: S2sTokenService,
    private val appContext: ApplicationContext,
) : OncePerRequestFilter() {
    override fun doFilterInternal(request: HttpServletRequest, response: HttpServletResponse, chain: FilterChain) {
        val authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION)
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            chain.doFilter(request, response)
            return
        }
        if (SecurityContextHolder.getContext().authentication != null) {
            chain.doFilter(request, response)
            return
        }

        val allowedServices = getAuthenticatedAnnotation(request)?.services
        val jws: Jws<Claims>
        try {
            jws = jwtService.validateAuthToken(authorizationHeader.substring(7), allowedServices)
        } catch (ex: ForbiddenException) {
            response.status = 403
            return
        } catch (ex: Exception) {
            response.status = 401
            return
        }

        val authentication = UsernamePasswordAuthenticationToken(jws.payload, null, listOf())
        authentication.details = WebAuthenticationDetailsSource().buildDetails(request)

        SecurityContextHolder.getContext().authentication = authentication
        chain.doFilter(request, response)
    }

    private fun getAuthenticatedAnnotation(request: HttpServletRequest): Authenticated? {
        val handlerExeChain = (appContext.getBean("requestMappingHandlerMapping") as RequestMappingHandlerMapping)
            .getHandler(request)!!
        val handlerMethod = handlerExeChain.handler as HandlerMethod
        val classAnnotation = handlerMethod.getClassAuthenticated() ?: return handlerMethod.getMethodAuthenticated()
        val methodAnnotation = handlerMethod.getMethodAnnotation(Authenticated::class.java) ?: return classAnnotation
        return Authenticated(classAnnotation.services + methodAnnotation.services)
    }

    private fun HandlerMethod.getClassAuthenticated() =
        this.method.declaringClass.getAnnotation(Authenticated::class.java)

    private fun HandlerMethod.getMethodAuthenticated() = this.getMethodAnnotation(Authenticated::class.java)
}
