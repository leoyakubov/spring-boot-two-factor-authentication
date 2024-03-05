package me.leoyakubov.authserver.endpoint;

import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import me.leoyakubov.authserver.exception.BadRequestException;
import me.leoyakubov.authserver.exception.EmailAlreadyExistsException;
import me.leoyakubov.authserver.exception.UsernameAlreadyExistsException;
import me.leoyakubov.authserver.model.Profile;
import me.leoyakubov.authserver.model.Role;
import me.leoyakubov.authserver.model.User;
import me.leoyakubov.authserver.payload.JwtAuthenticationResponse;
import me.leoyakubov.authserver.payload.LoginRequest;
import me.leoyakubov.authserver.payload.SignUpRequest;
import me.leoyakubov.authserver.payload.SignupResponse;
import me.leoyakubov.authserver.payload.VerifyCodeRequest;
import me.leoyakubov.authserver.service.TotpManager;
import me.leoyakubov.authserver.service.UserService;
import java.net.URI;

@RestController
@Slf4j
public class AuthEndpoint {

    @Autowired private UserService userService;
    @Autowired private TotpManager totpManager;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        String token = userService.loginUser(loginRequest.getUsername(), loginRequest.getPassword());
        return ResponseEntity.ok(new JwtAuthenticationResponse(token, StringUtils.isEmpty(token)));
    }

    @PostMapping("/verify")
    public ResponseEntity<?> verifyCode(@Valid @RequestBody VerifyCodeRequest verifyCodeRequest) {
        String token = userService.verify(verifyCodeRequest.getUsername(), verifyCodeRequest.getCode());
        return ResponseEntity.ok(new JwtAuthenticationResponse(token, StringUtils.isEmpty(token)));
    }

    @PostMapping(value = "/users", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> createUser(@Valid @RequestBody SignUpRequest payload) {
        log.info("creating user {}", payload.getUsername());

        User user = User
                .builder()
                .username(payload.getUsername())
                .email(payload.getEmail())
                .password(payload.getPassword())
                .userProfile(Profile
                        .builder()
                        .displayName(payload.getName())
                        .build())
                .mfa(payload.isMfa())
                .build();

        User saved;
        try {
             saved = userService.registerUser(user, Role.USER);
        } catch (UsernameAlreadyExistsException | EmailAlreadyExistsException e) {
            throw new BadRequestException(e.getMessage());
        }

        URI location = ServletUriComponentsBuilder
                .fromCurrentContextPath().path("/users/{username}")
                .buildAndExpand(user.getUsername()).toUri();

        return ResponseEntity
                .created(location)
                .body(new SignupResponse(saved.isMfa(),
                        totpManager.getUriForImage(saved.getSecret())));
    }
}
