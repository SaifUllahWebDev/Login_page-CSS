<?php
// Database connection
require('db.php');

// Initialize variables
$errors = [];
$success = "";
$login_errors = [];
$login_success = "";

// Handle registration form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['register'])) {
    $name = trim($_POST['name']);
    $email = trim($_POST['email']);
    $password = $_POST['password'];
    $confirm_password = $_POST['confirm_password'];

    // Registration validation
    if (empty($name) || empty($email) || empty($password) || empty($confirm_password)) {
        $errors[] = "All fields are required.";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Invalid email format.";
    } elseif ($password !== $confirm_password) {
        $errors[] = "Passwords do not match.";
    } elseif (strlen($password) < 6) {
        $errors[] = "Password must be at least 6 characters long.";
    } else {
        // Check if email already exists
        $stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows > 0) {
            $errors[] = "Email is already registered.";
        } else {
            // Hash the password
            $hashed_password = password_hash($password, PASSWORD_DEFAULT);

            // Insert into database
            $stmt = $conn->prepare("INSERT INTO users (name, email, password) VALUES (?, ?, ?)");
            $stmt->bind_param("sss", $name, $email, $hashed_password);
            if ($stmt->execute()) {
                $success = "Registration successful!";
            } else {
                $errors[] = "Registration failed. Please try again.";
            }
        }
        $stmt->close();
    }
}

// Handle login form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    $email = trim($_POST['email']);
    $password = $_POST['password'];

    // Login validation
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
                $login_errors[] = "Incorrect password. Please try again.";
            }
        } else {
            $login_errors[] = "No account found with this email.";
        }
        $stmt->close();
    }
}

$conn->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Authentication</title>
    <link rel="stylesheet" href="style.css" />
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css">
    <script>
        function showAlerts() {
            <?php if (!empty($errors)): ?>
                <?php foreach ($errors as $error): ?>
                    alert("<?php echo $error; ?>");
                <?php endforeach; ?>
            <?php endif; ?>

            <?php if (!empty($success)): ?>
                alert("<?php echo $success; ?>");
            <?php endif; ?>

            <?php if (!empty($login_errors)): ?>
                <?php foreach ($login_errors as $error): ?>
                    alert("<?php echo $error; ?>");
                <?php endforeach; ?>
            <?php endif; ?>

            <?php if (!empty($login_success)): ?>
                alert("<?php echo $login_success; ?>");
            <?php endif; ?>
        }
    </script>
</head>
<body onload="showAlerts()">
    <div class="container" id="container">
        <div class="form-container sign-up">
            <form action="index.php" method="post">
                <h1>Create Account</h1>
                <div class="social-icons">
                    <a href="#" class="icon"><i class="fa-brands fa-google-plus-g"></i></a>
                    <a href="#" class="icon"><i class="fa-brands fa-facebook-f"></i></a>
                    <a href="#" class="icon"><i class="fa-brands fa-github"></i></a>
                    <a href="#" class="icon"><i class="fa-brands fa-linkedin-in"></i></a>
                </div>
                <span>or use your email for registration</span>
                <input type="text" name="name" placeholder="Name" value="<?php echo htmlspecialchars($_POST['name'] ?? ''); ?>" />
                <input type="email" name="email" placeholder="Email" value="<?php echo htmlspecialchars($_POST['email'] ?? ''); ?>" />
                <input type="password" name="password" placeholder="Password" />
                <input type="password" name="confirm_password" placeholder="Confirm Password" />
                <button type="submit" name="register">Sign Up</button>
            </form>
        </div>
        <div class="form-container sign-in">
            <form action="index.php" method="post">
                <h1>Sign In</h1>
                <div class="social-icons">
                    <a href="#" class="icon"><i class="fa-brands fa-google-plus-g"></i></a>
                    <a href="#" class="icon"><i class="fa-brands fa-facebook-f"></i></a>
                    <a href="#" class="icon"><i class="fa-brands fa-github"></i></a>
                    <a href="#" class="icon"><i class="fa-brands fa-linkedin-in"></i></a>
                </div>
                <span>or use your email and password</span>
                <input type="email" name="email" placeholder="Email" />
                <input type="password" name="password" placeholder="Password" />
                <a href="#">Forgot Your Password?</a>
                <button type="submit" name="login">Sign In</button>
            </form>
        </div>
        <div class="toggle-container">
            <div class="toggle">
                <div class="toggle-panel toggle-left">
                    <h1>Welcome Back</h1>
                    <p>Enter your personal details to use all site features</p>
                    <button class="hidden" id="login">Sign In</button>
                </div>
                <div class="toggle-panel toggle-right">
                    <h1>Hello, Friend!</h1>
                    <p>Register with your personal details to use all site features</p>
                    <button class="hidden" id="register">Sign Up</button>
                </div>
            </div>
        </div>
    </div>
</body>
<script src="script.js"></script>
</html>
