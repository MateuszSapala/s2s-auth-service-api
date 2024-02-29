package sapala.s2sauthservice.api.security

@Target(AnnotationTarget.CLASS, AnnotationTarget.FUNCTION)
annotation class Authenticated(val services: Array<String>)
