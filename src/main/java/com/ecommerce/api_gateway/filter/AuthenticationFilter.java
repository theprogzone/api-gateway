package com.ecommerce.api_gateway.filter;

import com.ecommerce.api_gateway.exception.ValidationException;
import jakarta.validation.constraints.Size;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.List;

@Component
@Slf4j
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    @Autowired
    private WebClient.Builder webClientBuilder;

    @Autowired
    private RestTemplate restTemplate;

    public AuthenticationFilter() {
        super(Config.class);
    }

    List<String> urls = List.of("user/login", "user/register");

    @Override
    @SneakyThrows
    public GatewayFilter apply(Config config) {

        return (((exchange, chain) -> {
            if (isAuthenticate(exchange.getRequest().getURI().getPath())) {
                if (!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                    throw new ValidationException("Missing authorization header in the request");
                }

                String authHeader = exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
                if (authHeader != null && authHeader.startsWith("Bearer ")) {
                    authHeader = authHeader.substring(7);
                }

                /*try {
                    String response = webClientBuilder.build().get().uri("http://auth-service/auth/api/v1/user/validateToken?token="+authHeader).retrieve().bodyToMono(String.class).to;

                } catch (Exception e) {
                    log.error("API error: "+e.getMessage());
                    throw new ValidationException("Invalid token");
                }*/

                try {
                    restTemplate.getForObject("http://localhost:8081/auth/api/v1/user/validateToken?token="+authHeader, String.class);

                } catch (Exception e) {
                    log.error("API error: "+e.getMessage());
                    throw new ValidationException("Invalid token");
                }


            }
            return chain.filter(exchange);
        }));
    }

    private boolean isAuthenticate(String requestUrl) {
        log.info(requestUrl);
        if (urls.stream().filter(u -> requestUrl.contains(u)).findFirst().isPresent()) {
            return false;
        }
        return true;
    }

    public static class Config {

    }
}
