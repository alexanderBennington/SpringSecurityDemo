package alexander.SpringSecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@Configuration
@EnableWebSecurity //se establece que es clase de configuración de security
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception{
        return httpSecurity
                //.csrf(csrf -> csrf.disable()) Cross-site request forgery vulnerabilidad en formularios,
                //se deshabilita cuando no se trabaja con forms directamente desde navegador
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/v1/index2") // Peticiones que coincidan con endpoints
                        .permitAll() // sin necesidad de autenticar
                        .anyRequest()
                        .authenticated() // Los demas si deben autenticarse
                )
                .formLogin(formLoginConfigurer ->
                    formLoginConfigurer
                        .successHandler(successHandler()) //redirigir al iniciar sesion
                        .permitAll()
                )
                .sessionManagement(session ->
                    session
                        .sessionFixation(sessionFixationConfigurer ->
                            sessionFixationConfigurer.migrateSession()
                        ) //Si se detecta un ataque se cambia la sesión a otra ID
                        .sessionCreationPolicy(SessionCreationPolicy.ALWAYS)
                        .invalidSessionUrl("/login")
                        .maximumSessions(1)
                        .expiredUrl("/login")
                ) //Va a crear una sesion siempre y cuando no exista alguna otra
                .build();
    }

    public AuthenticationSuccessHandler successHandler(){
        return ((request, response, authentication) -> {
            response.sendRedirect("/v1/index");
        });
    }
}
