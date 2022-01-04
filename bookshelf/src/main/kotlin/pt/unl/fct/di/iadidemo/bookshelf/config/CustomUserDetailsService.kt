package pt.unl.fct.di.iadidemo.bookshelf.config

import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint
import org.springframework.stereotype.Component
import org.springframework.stereotype.Service
import pt.unl.fct.di.iadidemo.bookshelf.application.services.UserService
import java.io.PrintWriter
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

data class CustomUserDetails(
    private val username:String,
    private val password:String,
    private val authorities:MutableCollection<out GrantedAuthority>) : UserDetails {

    override fun getAuthorities(): MutableCollection<out GrantedAuthority> = authorities

    override fun isEnabled(): Boolean = true

    override fun getUsername(): String = username

    override fun isCredentialsNonExpired(): Boolean = true

    override fun getPassword(): String = password

    override fun isAccountNonExpired(): Boolean = true

    override fun isAccountNonLocked(): Boolean = true
}


@Service
class CustomUserDetailsService(val users: UserService) : UserDetailsService {

    override fun loadUserByUsername(username: String?): UserDetails {

        username?.let {
            val user =
                users.findUser(username)
                .orElseThrow { UsernameNotFoundException(username) }
                .let {
                    CustomUserDetails(
                        it.username,
                        it.password,
                        it.roles.map { SimpleGrantedAuthority("ROLE_${it.tag}") }.toMutableList() )
                }
            return user
        }
        throw UsernameNotFoundException("")
    }
}

@Component
class CustomEntryPoint : BasicAuthenticationEntryPoint() {

    override fun commence(request: HttpServletRequest?, response: HttpServletResponse?, authException: AuthenticationException?) {
        if (response != null) {
            response.addHeader("WWW-Authenticate", "xBasic")
            response.status = HttpServletResponse.SC_UNAUTHORIZED
            val writer:PrintWriter = response.writer
            if (authException != null) {
                writer.println("HTTP Status 401 - " + authException.message)
            }
        }
    }

    override fun afterPropertiesSet() {
        realmName = "Bookshelf"
        super.afterPropertiesSet()
    }
}