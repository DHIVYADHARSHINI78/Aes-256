<?php
class JsonMiddleware {
    public static function handle() {
        if ($_SERVER['REQUEST_METHOD'] === 'POST' || $_SERVER['REQUEST_METHOD'] === 'PUT') {
            $input = file_get_contents('php://input');
            $data = json_decode($input, true);

            if (json_last_error() !== JSON_ERROR_NONE) {
                Response::json(["error" => "Invalid JSON payload"], 400);
            }
            $GLOBALS['request_data'] = $data;
        }
    }
}