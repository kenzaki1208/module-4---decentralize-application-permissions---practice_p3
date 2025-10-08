package org.example.demobuildingjwtwithdatabase.jwt.config;

import org.example.demobuildingjwtwithdatabase.jwt.CustomAccessDeniedHandler;
import org.example.demobuildingjwtwithdatabase.jwt.JwtAuthenticationTokenFilter;
import org.example.demobuildingjwtwithdatabase.jwt.RestAuthenticationEntryPoint;
import org.example.demobuildingjwtwithdatabase.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration // Đánh dấu lớp này là lớp cấu hình
@EnableWebSecurity // Kích hoạt Spring Security cho ứng dụng
public class SecurityConfig {

    @Autowired
    private UserService userService; // Service để load user từ database

    // Bean tạo filter kiểm tra JWT trong mỗi request
    @Bean
    public JwtAuthenticationTokenFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationTokenFilter();
    }

    // Bean cung cấp AuthenticationManager để xử lý đăng nhập
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    // Cấu hình Provider để xác thực người dùng dựa trên DB và password encoder
    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userService); // sử dụng userService để lấy user từ DB
        authProvider.setPasswordEncoder(passwordEncoder()); // sử dụng mã hoá BCrypt
        return authProvider;
    }

    // Mã hóa mật khẩu sử dụng BCrypt
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(10); // độ mạnh 10 vòng
    }

    // Xử lý lỗi khi chưa đăng nhập (401 Unauthorized)
    @Bean
    public RestAuthenticationEntryPoint restServicesEntryPoint() {
        return new RestAuthenticationEntryPoint();
    }

    // Xử lý lỗi khi đã đăng nhập nhưng không đủ quyền (403 Forbidden)
    @Bean
    public CustomAccessDeniedHandler customAccessDeniedHandler() {
        return new CustomAccessDeniedHandler();
    }

    // Cấu hình chuỗi lọc bảo mật
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable) // Tắt CSRF vì API không cần
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/api/login").permitAll() // Cho phép mọi người truy cập login API
                        .requestMatchers(HttpMethod.GET, "/api/**").hasAnyRole("ADMIN", "USER") // GET yêu cầu quyền USER hoặc ADMIN
                        .requestMatchers(HttpMethod.POST, "/api/**").hasRole("ADMIN") // POST chỉ ADMIN mới có quyền
                        .requestMatchers(HttpMethod.DELETE, "/api/**").hasRole("ADMIN") // DELETE chỉ ADMIN mới có quyền
                        .anyRequest().authenticated() // Các request khác yêu cầu đăng nhập
                )
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(restServicesEntryPoint()) // Nếu chưa đăng nhập → trả về lỗi 401
                        .accessDeniedHandler(customAccessDeniedHandler()) // Nếu đã đăng nhập nhưng không đủ quyền → trả về lỗi 403
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // Không dùng session, hoàn toàn dựa trên JWT
                )
                .authenticationProvider(authenticationProvider()) // Áp dụng provider dùng DB và encoder
                .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class); // Thêm JWT filter trước khi xử lý login/password

        return http.build(); // Trả về đối tượng cấu hình filter chain
    }
}
