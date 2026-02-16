<?php
session_start();
require_once dirname(__DIR__) . '/config/config.php';

spl_autoload_register(function ($class) {
    $basePath = dirname(__DIR__) . '/app/';
    $paths = ['controllers/', 'models/', 'helpers/', 'core/', 'middleware/'];
    foreach ($paths as $path) {
        $file = $basePath . $path . $class . '.php';
        if (file_exists($file)) {
            require_once $file;
            return;
        }
    }
});

JsonMiddleware::handle();
CsrfMiddleware::handle();
  
$router = new Router();


$router->post('/api/register', 'AuthController', 'register');
$router->post('/api/login', 'AuthController', 'login');
$router->post('/api/refresh', 'AuthController', 'refresh');
$router->post('/api/logout', 'AuthController', 'logout', false);
$router->get('/api/patients', 'PatientController', 'index', true);
$router->post('/api/patients', 'PatientController', 'create', true);
$router->put('/api/patients', 'PatientController', 'update', true);
$router->patch('/api/patients', 'PatientController', 'patch', true);
$router->delete('/api/patients', 'PatientController', 'delete', true);

$router->resolve();