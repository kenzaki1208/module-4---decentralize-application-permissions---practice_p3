package org.example.demobuildingjwtwithdatabase.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.example.demobuildingjwtwithdatabase.jwt.service.JwtService;
import org.example.demobuildingjwtwithdatabase.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

// Đánh dấu lớp này là một Component để Spring tự động quản lý và inject vào chuỗi filter
@Component
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {

    @Autowired
    private JwtService jwtService; // Service hỗ trợ xử lý JWT: kiểm tra, giải mã,...

    @Autowired
    private UserService userService; // Service để tải thông tin User từ database

    // Phương thức chính của filter, sẽ được gọi mỗi lần có HTTP request
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {
        try {
            // Lấy token JWT từ header Authorization của request
            String jwt = getJwtFromRequest(request);

            // Kiểm tra token không null và hợp lệ (chưa hết hạn, đúng chữ ký,...)
            if (jwt != null && jwtService.validateJwtToken(jwt)) {
                // Lấy username từ token
                String username = jwtService.getUsernameFromJwtToken(jwt);

                // Tải thông tin UserDetails từ database dựa vào username
                UserDetails userDetails = userService.loadUserByUsername(username);

                // Tạo đối tượng Authentication của Spring Security dựa trên thông tin user
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());

                // Thiết lập thêm các chi tiết của request (IP, session, ...)
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Đặt Authentication vào trong SecurityContext để đánh dấu user đã được xác thực
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception e) {
            // Log lỗi nếu có vấn đề trong quá trình xác thực
            logger.error("Can NOT set user authentication -> Message: {}", e);
        }

        // Tiếp tục chuỗi filter, để các filter tiếp theo hoặc controller xử lý
        filterChain.doFilter(request, response);
    }

    // Hàm lấy token JWT từ header "Authorization" (theo chuẩn Bearer token)
    private String getJwtFromRequest(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        // Kiểm tra header có tồn tại và bắt đầu bằng "Bearer "
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            // Trả về phần token, loại bỏ chữ "Bearer "
            return authHeader.replace("Bearer ", "");
        }
        // Nếu không có token hợp lệ thì trả về null
        return null;
    }
}
