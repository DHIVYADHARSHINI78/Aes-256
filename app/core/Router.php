<?php

class Router {
    private $routes = [];

    public function post($path, $controller, $method, $protected = false) {
        $this->routes['POST'][$path] = ['controller' => $controller, 'method' => $method, 'protected' => $protected];
    }

    public function get($path, $controller, $method, $protected = false) {
        $this->routes['GET'][$path] = ['controller' => $controller, 'method' => $method, 'protected' => $protected];
    }

    public function put($path, $controller, $method, $protected = false) {
        $this->routes['PUT'][$path] = ['controller' => $controller, 'method' => $method, 'protected' => $protected];
    }

    public function patch($path, $controller, $method, $protected = false) {
        $this->routes['PATCH'][$path] = ['controller' => $controller, 'method' => $method, 'protected' => $protected];
    }

    public function delete($path, $controller, $method, $protected = false) {
        $this->routes['DELETE'][$path] = ['controller' => $controller, 'method' => $method, 'protected' => $protected];
    }


    public function resolve() {
        $method = $_SERVER['REQUEST_METHOD'];
        $uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

        $path = str_replace(['/JWT-Authentication/public', '/JWT-Authentication'], '', $uri);

        if (isset($this->routes[$method][$path])) {
            $route = $this->routes[$method][$path];

            if ($route['protected']) {
                $GLOBALS['user'] = AuthMiddleware::handle();
            }

            $controllerName = $route['controller'];
            $methodName = $route['method'];
            
            if (class_exists($controllerName)) {
                $controller = new $controllerName();

                if ($method === 'GET' && $path === '/api/patients' && isset($_GET['id'])) {
                    $controller->show();
                } else {
                    
                    $controller->$methodName();
                }
              

            } else {
                header('Content-Type: application/json');
                http_response_code(500);
                echo json_encode(['error' => "Controller $controllerName not found"]);
            }
        } else {
            header('Content-Type: application/json');
            http_response_code(404);
            echo json_encode(['error' => 'Route not found', 'debug_path' => $path]);
        }
    }
}