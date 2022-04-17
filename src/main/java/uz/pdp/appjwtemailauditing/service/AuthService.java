package uz.pdp.appjwtemailauditing.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import uz.pdp.appjwtemailauditing.config.JwtProvider;
import uz.pdp.appjwtemailauditing.entity.User;
import uz.pdp.appjwtemailauditing.entity.enums.ERole;
import uz.pdp.appjwtemailauditing.payload.ApiResponse;
import uz.pdp.appjwtemailauditing.payload.LoginDto;
import uz.pdp.appjwtemailauditing.payload.RegisterDto;
import uz.pdp.appjwtemailauditing.repository.RoleRepository;
import uz.pdp.appjwtemailauditing.repository.UserRepository;

import java.util.Collections;
import java.util.Optional;
import java.util.UUID;

@Service
public class AuthService implements UserDetailsService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RoleRepository roleRepository;
    private final JavaMailSender javaMailSender;
    private final AuthenticationManager authenticationManager;


    private final JwtProvider jwtProvider;

    @Autowired
    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder, RoleRepository roleRepository, JavaMailSender javaMailSender, AuthenticationManager authenticationManager, JwtProvider jwtProvider) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.roleRepository = roleRepository;
        this.javaMailSender = javaMailSender;
        this.authenticationManager = authenticationManager;
        this.jwtProvider = jwtProvider;
    }


    public ApiResponse register(RegisterDto registerDto){

        boolean existsByEmail = userRepository.existsByEmail(registerDto.getEmail());

        if (existsByEmail){
            return new ApiResponse("This email is already exist!",false);
        }

        User user = new User();
        user.setFirstName(registerDto.getFirstName());
        user.setLastName(registerDto.getLastName());
        user.setEmail(registerDto.getEmail());
        user.setPassword(passwordEncoder.encode(registerDto.getPassword()));
        user.setRoles(Collections.singleton(roleRepository.findByRoleName(ERole.ROLE_USER)));
        user.setEmailCode(UUID.randomUUID().toString());

        userRepository.save(user);
        sendEmail(user.getEmail(), user.getEmailCode());


        return new ApiResponse("Verify Email!", true);
    }

    private Boolean sendEmail(String sendingEmail, String emailCode){
        try {
            SimpleMailMessage mailMessage = new SimpleMailMessage();
            mailMessage.setFrom("noreply@gmail.com");
            mailMessage.setTo(sendingEmail);
            mailMessage.setSubject("Verify Account");
            mailMessage.setText("<a href = 'http://localhost:8080/api/auth/verifyEmail?emailCode=" + emailCode +"&email="+sendingEmail + "'>Verify Email</a>");
            javaMailSender.send(mailMessage);
            return true;
        }catch (Exception ex){
            return false;
        }
    }

    public ApiResponse verifyEmail(String emailCode, String email) {
        Optional<User> byEmailAndEmailCode = userRepository.findByEmailAndEmailCode(email, emailCode);
        if(byEmailAndEmailCode.isPresent()){
            User user = byEmailAndEmailCode.get();
            user.setEnabled(true);
            user.setEmailCode(null);
            userRepository.save(user);
            return new ApiResponse("Email is verified!", true);
        }
        return new ApiResponse("Email is already verified!", false);

    }

    public ApiResponse login(LoginDto loginDto) {
        try {
            Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    loginDto.getUsername(),
                    loginDto.getPassword()
            ));
            User user = (User)authentication.getPrincipal();
            String token = jwtProvider.generateToken(user.getUsername(), user.getRoles());
            return new ApiResponse("Token", true, token );
        }catch (BadCredentialsException ex){
            return new ApiResponse("Username or password is wrong!", false);
        }
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        return userRepository.findByEmail(username).orElseThrow(()-> new UsernameNotFoundException(username + "is not found!"));
    }
}
