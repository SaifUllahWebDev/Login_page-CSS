<?php
// Database connection
require('db.php');

// Initialize variables
$login_errors = [];
$login_success = "";

// Handle login form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    $email = trim($_POST['email']);
    $password = $_POST['password'];

    // Validation
    if (empty($email) || empty($password)) {
        $login_errors[] = "Both fields are required.";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $login_errors[] = "Invalid email format.";
    } else {
        // Check user in database
        $stmt = $conn->prepare("SELECT id, password FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows > 0) {
            $stmt->bind_result($user_id, $hashed_password);
            $stmt->fetch();

            // Verify password
            if (password_verify($password, $hashed_password)) {
                $login_success = "Login successful!";
                // Start session or redirect to dashboard
                session_start();
                $_SESSION['user_id'] = $user_id;
                header("Location: home.php"); // Replace with your dashboard page
                exit;
            } else {
                $login_errors[] = "Invalid email or password.";
            }
        } else {
            
            $login_errors[] = "No account found with this email.";
        }
        $stmt->close();
    }
}

$conn->close();
?>
