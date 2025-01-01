<?php
// Start the session
session_start();

// Check if the user is logged in
if (isset($_SESSION['user_id'])) {
    // Logout functionality
    if (isset($_POST['logout'])) {
        // Destroy the session
        session_destroy();

        // Redirect to login page
        header("Location: index.php"); // Replace with the login page URL
        exit;
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Home</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            text-align: center;
            background-color: #f4f4f9;
            margin: 0;
            padding: 0;
        }

        h1 {
            color: #333;
            margin-top: 20px;
        }

        form {
            margin-top: 20px;
        }

        button {
            background-color: #007BFF;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
            transition: background-color 0.3s ease;
        }

        button:hover {
            background-color: #0056b3;
        }
    </style>
</head>
<body>
    <h1>WELCOME TO THE WEBSITE!</h1>
    <form action="home.php" method="post">
        <button type="submit" name="logout">Logout</button>
    </form>
</body>
</html>
