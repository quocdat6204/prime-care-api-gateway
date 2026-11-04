package com.example.api_gateway.config;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    private final WebClient.Builder webClientBuilder;

    // Danh sách API không check Bearer token ở Gateway
    private static final List<String> publicEndpoints = List.of(
            "/authenticate/login",
            "/authenticate/register",
            "/authenticate/generate-otp",
            "/authenticate/verify-otp",
            "/authenticate/forgot-password",
            "/authenticate/refresh",
            "/emails/send", // Cho qua thẳng để email-service tự kiểm tra Basic Auth nội bộ
            "/internal/clinic", // Cho qua thẳng để clinic-service tự kiểm tra Internal API Key
            "/api/vnpay/payment-return",
            "/api/vnpay/payment-ipn",
            "/users/doctors"
    );

    public AuthenticationFilter(WebClient.Builder webClientBuilder) {
        super(Config.class);
        this.webClientBuilder = webClientBuilder;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();

            // 1. Kiểm tra nếu là API trong danh sách bypass thì cho qua thẳng
            if (publicEndpoints.stream().anyMatch(uri -> request.getURI().getPath().contains(uri))) {
                return chain.filter(exchange);
            }

            // 2. Kiểm tra sự tồn tại của Authorization Header
            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                return onError(exchange, HttpStatus.UNAUTHORIZED);
            }

            String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return onError(exchange, HttpStatus.UNAUTHORIZED);
            }

            // 3. Gọi không đồng bộ (Reactive) sang user-service qua WebClient
            return webClientBuilder.build()
                    .post()
                    .uri("http://user-service/authenticate/checkToken")
                    .header(HttpHeaders.AUTHORIZATION, authHeader)
                    .retrieve()
                    .toBodilessEntity()
                    .flatMap(response -> chain.filter(exchange)) // Thành công -> đi tiếp
                    .onErrorResume(throwable -> onError(exchange, HttpStatus.UNAUTHORIZED)); // Thất bại -> 401
        };
    }

    private Mono<Void> onError(ServerWebExchange exchange, HttpStatus status) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);
        return response.setComplete();
    }

    public static class Config {}
}
