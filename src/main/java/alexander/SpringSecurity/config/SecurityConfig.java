package alexander.SpringSecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

//import static org.springframework.security.config.Customizer.withDefaults;

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
                        .sessionRegistry(sessionRegistry())
                ) //Va a crear una sesion siempre y cuando no exista alguna otra
                //.httpBasic(withDefaults()) En caso de configuraciones basicas, envio de 
                                            //credenciales en header de endpoint
                .build();
    }

    @Bean
    public SessionRegistry sessionRegistry(){
        return new SessionRegistryImpl();
    }

    public AuthenticationSuccessHandler successHandler(){
        return ((request, response, authentication) -> {
            response.sendRedirect("/v1/session");
        });
    }
}
