package com.ecommerce.api_gateway.filter;

import com.ecommerce.api_gateway.exception.ValidationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.List;

@Component
@Slf4j
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    @Autowired
    private WebClient.Builder webClientBuilder;

    public AuthenticationFilter() {
        super(Config.class);
    }

    List<String> urls = List.of("user/login", "user/register");

    @Override
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

                webClientBuilder.build().get().uri("http://auth-service/auth/api/v1/user/validateToken?token=" + authHeader)
                        .exchangeToMono(response -> {
                            int statusCode = response.statusCode().value();
                            log.info("HTTP response code: {}", statusCode);
                            if (statusCode != 200) {
                                log.error("Status code: {}", statusCode);
                                exchange.getResponse().setStatusCode(HttpStatus.BAD_REQUEST);
                                return exchange.getResponse().setComplete();
                            }
                            return chain.filter(exchange);
                        }).subscribe();

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
