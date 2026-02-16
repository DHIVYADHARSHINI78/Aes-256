<?php
class PatientController {
    public function index() {
        $userId = $GLOBALS['user']['user_id'];
        $patientModel = new Patient();
        $patients = $patientModel->getAll($userId);
        Response::json(["data" => $patients]);
    }

    public function show() {
        $id = $_GET['id'] ?? null;
        $userId = $GLOBALS['user']['user_id'];

        if (!$id || !is_numeric($id)) {
            Response::json(['error' => 'Valid ID required'], 400);
            return;
        }

        $patientModel = new Patient();
        $patient = $patientModel->findById($id, $userId);

        if ($patient) {
            // Decrypt contact for display and hide encrypted fields
            if ($patient['contact_encrypted']) {
                $patient['contact'] = AES::decrypt($patient['contact_encrypted']);
            }
            unset($patient['contact_encrypted'], $patient['contact_hash']);
            Response::json($patient);
        } else {
            Response::json(['error' => '403 Forbidden: Access Denied'], 403);
        }
    }

    public function create() {
        $data = $GLOBALS['request_data'];
        $userId = $GLOBALS['user']['user_id'];
        $required_fields = ['name', 'age', 'gender', 'contact', 'address'];

        foreach ($required_fields as $field) {
            if (empty($data[$field])) {
                Response::json(['error' => ucfirst($field) . " is required"], 400);
                return;
            }
        }

        if (!is_numeric($data['age']) || $data['age'] <= 0) {
            Response::json(['error' => 'Age must be a number greater than 0'], 400);
            return;
        }

        // Normalize, encrypt, and hash the contact (phone)
        $normalizedContact = preg_replace('/\D/', '', $data['contact']); // Keep only digits
        if (strlen($normalizedContact) !== 10) {  // Assuming 10-digit phone
            Response::json(['error' => 'Contact must be exactly 10 digits'], 400);
            return;
        }
        $contactEncrypted = AES::encrypt($normalizedContact);
        $contactHash = AES::generateHash($normalizedContact);

        $patientModel = new Patient();
        $success = $patientModel->create($data['name'], $data['age'], $data['gender'], $contactEncrypted, $contactHash, $data['address'], $userId);

        if ($success) {
            Response::json(['message' => 'Patient added successfully'], 201);
        } else {
            Response::json(['error' => 'Failed to add patient'], 500);
        }
    }

    public function update() {
        $id = $_GET['id'] ?? null;
        $userId = $GLOBALS['user']['user_id'];
        $data = $GLOBALS['request_data'];

        if (!$id || !is_numeric($id)) {
            Response::json(['error' => 'Valid ID required'], 400);
            return;
        }

        $patientModel = new Patient();
        if (!$patientModel->findById($id, $userId)) {
            Response::json(['error' => '403 Forbidden: You cannot update this patient'], 403);
            return;
        }

        // Handle contact encryption if provided
        $contactEncrypted = null;
        $contactHash = null;
        if (!empty($data['contact'])) {
            $normalizedContact = preg_replace('/\D/', '', $data['contact']);
            if (strlen($normalizedContact) !== 10) {
                Response::json(['error' => 'Contact must be exactly 10 digits'], 400);
                return;
            }
            $contactEncrypted = AES::encrypt($normalizedContact);
            $contactHash = AES::generateHash($normalizedContact);
        }

        $success = $patientModel->update($id, $data['name'], $data['age'], $data['gender'], $contactEncrypted, $contactHash, $data['address'], $userId);

        if ($success) {
            Response::json(['message' => 'Patient updated successfully']);
        } else {
            Response::json(['error' => 'Update failed'], 500);
        }
    }

    public function patch() {
        $id = $_GET['id'] ?? null;
        $userId = $GLOBALS['user']['user_id'];
        $data = $GLOBALS['request_data'];

        if (!$id || !is_numeric($id) || empty($data)) {
            Response::json(['error' => 'Valid ID and data required'], 400);
            return;
        }

        $patientModel = new Patient();
        if (!$patientModel->findById($id, $userId)) {
            Response::json(['error' => '403 Forbidden: You cannot update this patient'], 403);
            return;
        }

        // Handle contact encryption if provided in patch data
        if (!empty($data['contact'])) {
            $normalizedContact = preg_replace('/\D/', '', $data['contact']);
            if (strlen($normalizedContact) !== 10) {
                Response::json(['error' => 'Contact must be exactly 10 digits'], 400);
                return;
            }
            $data['contact_encrypted'] = AES::encrypt($normalizedContact);
            $data['contact_hash'] = AES::generateHash($normalizedContact);
            unset($data['contact']); // Remove plain contact from data
        }

        $success = $patientModel->patchUpdate($id, $data, $userId);

        if ($success) {
            Response::json(['message' => 'Patient partially updated successfully']);
        } else {
            Response::json(['error' => 'Patch update failed'], 500);
        }
    }

    public function delete() {
        $id = $_GET['id'] ?? null;
        $userId = $GLOBALS['user']['user_id'];

        $patientModel = new Patient();
        $patient = $patientModel->findById($id, $userId);
        if (!$patient) {
            Response::json(['error' => 'Unauthorized access'], 403);
            return;
        }

        $patientModel->delete($id, $userId);
        Response::json(['message' => 'Deleted successfully']);
    }
}