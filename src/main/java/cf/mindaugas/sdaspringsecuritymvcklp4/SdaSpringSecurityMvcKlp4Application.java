package cf.mindaugas.sdaspringsecuritymvcklp4;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.apache.catalina.connector.Connector;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.servlet.server.ServletWebServerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.stereotype.Repository;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@SpringBootApplication
public class SdaSpringSecurityMvcKlp4Application {
    public static void main(String[] args) {
        SpringApplication.run(SdaSpringSecurityMvcKlp4Application.class, args);
    }
}

@Configuration
class HttpConfig {
    @Value("${server.http.port}")
    private int httpPort;

    @Bean // (it only works for springboot 2.x)
    public ServletWebServerFactory servletContainer(){
        TomcatServletWebServerFactory factory = new TomcatServletWebServerFactory();
        factory.addAdditionalTomcatConnectors(createStanderConnecter());
        return factory;
    }

    private Connector createStanderConnecter(){
        Connector connector =
                //new Connector("org.apache.coyote.http11.Http11NioProtocol");
                new Connector(TomcatServletWebServerFactory.DEFAULT_PROTOCOL);
        connector.setPort(httpPort);
        return connector;
    }
}

@Configuration
@EnableWebSecurity
class BasicSecurityConfiguration extends WebSecurityConfigurerAdapter {
    @Autowired
    private AuthUserDetailsService userDetailsService;

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(encoder());
        return authProvider;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(authenticationProvider());
    }

    // Plain text encoder: https://stackoverflow.com/questions/51208425/how-to-use-spring-security-without-password-encoding
    @Bean
    public PasswordEncoder encoder() {
        //return new PasswordEncoder() {
        //    @Override
        //    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        //        return rawPassword.toString().equals(encodedPassword);
        //    }
        //    @Override
        //    public String encode(CharSequence rawPassword) {
        //        return null;
        //    }
        //};

        return new BCryptPasswordEncoder();
    }



    //@Override
    //protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    //    auth.inMemoryAuthentication()
    //            .withUser("user").password("{noop}pass").roles("USER").and()
    //            .withUser("admin").password("{noop}admin").roles("USER", "ADMIN");
    //}

    //@Override
    //protected void configure(HttpSecurity http) throws Exception {
    //    http
    //    .authorizeRequests()
    //    .antMatchers("/").permitAll()
    //    .antMatchers("/profile").authenticated()
    //    .antMatchers("/admin").hasRole("ADMIN")
    //    //.anyRequest().authenticated()
    //    .and()
    //    .httpBasic();
    //}

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
            .antMatchers("/").permitAll()
            .antMatchers("/profile/**").authenticated()
            //.antMatchers("/admin/**").hasRole("ADMIN")
            .antMatchers("/admin/**").access("hasAuthority('ADMIN')")
            .and()
            .formLogin()
            .loginPage("/login")
            .permitAll().and()
            .logout()
            .logoutUrl("/logout")
            .invalidateHttpSession(true)
            .deleteCookies("JSESSIONID");
    }

}

@Controller
class PageController {
    @GetMapping("/")
    public String index(){
        return "index";
    }

    @GetMapping("/profile")
    public String profile(){
        return "profile/index";
    }

    @GetMapping("/admin")
    public String admin(){
        return "admin/index";
    }
}

@Controller
class AuthController {
    @GetMapping("/login")
    public String login(){
        return "login";
    }

    @RequestMapping(value="/logout", method = RequestMethod.GET)
    public String logout(HttpServletRequest request, HttpServletResponse response) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        //System.out.println(auth);
        if (auth != null) new SecurityContextLogoutHandler().logout(request, response, auth);
        //You can redirect wherever you want, but generally it's a good practice to show login screen again.
        return "redirect:/login";
    }
}

@Entity
@AllArgsConstructor
@NoArgsConstructor
@Data
class User implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;
    private String username;
    private String password;
    private boolean isBlocked;
    private String roles = "";
    private String authorities = "";

    public User(String username, String password, String roles, String authorities) {
        this.username = username;
        this.password = password;
        this.roles = roles;
        this.authorities = authorities;
        this.isBlocked = false;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Arrays.stream(this.roles.split(","))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }
}

@Repository
interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername(String username);
}

@Service
class DbInit implements CommandLineRunner {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) {
        this.userRepository.deleteAll();
        //User dan = new User("dan","dan123","USER","");
        //User admin = new User("admin","admin123","ADMIN","ACCESS_TEST1,ACCESS_TEST2");
        //User manager = new User("manager","manager123","MANAGER","ACCESS_TEST1");

         // Crete users
         User dan = new User("d", passwordEncoder.encode("d1"),"USER","");
         User admin = new User("a", passwordEncoder.encode("a1"),"ADMIN","ACCESS_TEST1,ACCESS_TEST2");
         User manager = new User("m", passwordEncoder.encode("m1"),"MANAGER","ACCESS_TEST1");

        List<User> users = Arrays.asList(dan,admin,manager);
        this.userRepository.saveAll(users);
    }
}

@Service
class AuthUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) {
        User user = userRepository.findByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException(username);
        }
        return user;
    }
}
