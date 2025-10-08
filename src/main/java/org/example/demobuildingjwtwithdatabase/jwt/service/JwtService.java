package org.example.demobuildingjwtwithdatabase.jwt.service;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.example.demobuildingjwtwithdatabase.model.UserPrinciple;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;

@Service  // Đánh dấu đây là service để Spring quản lý và inject khi cần
public class JwtService {

    // Khóa bí mật dùng để ký JWT (ở đây là chuỗi base64)
    private static final String SECRET_KEY = "123456789987654321123456789987654321123456789987654321123456789987654321";

    // Thời gian hiệu lực của token tính bằng milliseconds (1 ngày = 86400000ms)
    private static final long EXPIRE_TIME = 86400000L;

    // Phương thức tạo JWT token khi người dùng đăng nhập thành công
    public String generateTokenLogin(Authentication authentication) {
        // Lấy thông tin user đã đăng nhập (principal)
        UserPrinciple userPrincipal = (UserPrinciple) authentication.getPrincipal();

        // Xây dựng token JWT gồm các thông tin:
        // - subject: username của user
        // - issuedAt: thời điểm tạo token
        // - expiration: thời điểm token hết hạn (hiện tại + EXPIRE_TIME)
        // - signWith: ký token bằng khóa bí mật
        return Jwts.builder()
                .setSubject(userPrincipal.getUsername()) // username
                .setIssuedAt(new Date(System.currentTimeMillis())) // thời điểm hiện tại
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRE_TIME)) // hạn token
                .signWith(getSignInKey()) // ký token với khóa bí mật
                .compact(); // sinh chuỗi token
    }

    // Phương thức lấy Key ký token từ chuỗi SECRET_KEY
    private Key getSignInKey() {
        // Giải mã base64 chuỗi SECRET_KEY thành mảng byte
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        // Tạo đối tượng Key dùng thuật toán HMAC SHA cho việc ký token
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // Phương thức kiểm tra token có hợp lệ hay không
    public boolean validateJwtToken(String authToken) {
        try {
            // Phân tích (parse) token, nếu token hợp lệ, không lỗi thì trả về true
            Jwts.parserBuilder()
                    .setSigningKey(getSignInKey()) // thiết lập khóa ký
                    .build()
                    .parseClaimsJws(authToken); // phân tích token JWT
            return true;
        } catch (MalformedJwtException e) {
            System.out.println("Invalid JWT token -> Message: " + e.getMessage());
        } catch (ExpiredJwtException e) {
            System.out.println("Expired JWT token -> Message: " + e.getMessage());
        } catch (UnsupportedJwtException e) {
            System.out.println("Unsupported JWT token -> Message: " + e.getMessage());
        } catch (IllegalArgumentException e) {
            System.out.println("JWT claims string is empty -> Message: " + e.getMessage());
        }
        // Nếu xảy ra lỗi, token không hợp lệ hoặc hết hạn => trả về false
        return false;
    }

    // Phương thức lấy username (subject) từ token JWT
    public String getUsernameFromJwtToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignInKey()) // thiết lập khóa ký
                .build()
                .parseClaimsJws(token) // phân tích token
                .getBody() // lấy phần payload (claims)
                .getSubject(); // lấy giá trị subject (username)
    }
}