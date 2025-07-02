package alexander.SpringSecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

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
                .formLogin(withDefaults())
                .build();
    }
}
