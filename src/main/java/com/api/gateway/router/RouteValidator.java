package com.api.gateway.router;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import java.util.*;
import java.util.function.Predicate;
@Component
public class RouteValidator {
    public static final List<String> openApiEndPoints = List.of(
            "/api/auth/send-otp",
            "/api/auth/login",
            "/eureka-server",
            "/v1/products/shopify",
            "/v1/products/share/get"
    );

    public Predicate<ServerHttpRequest> isSecured =
    request -> openApiEndPoints
            .stream()
            .noneMatch(uri -> request.getURI().getPath().contains(uri));

}