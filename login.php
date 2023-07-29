<?php
$username = $_POST['username'];
$password = $_POST['password'];

// Database connection
$con = new mysqli('localhost', 'root', '', 'holla');
if ($con->connect_error) {
    die('Connection Failed: ' . $con->connect_error);
} else {
    // Check if the username exists in the database
    $stmt = $con->prepare("SELECT * FROM registerok WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $stmt_result = $stmt->get_result();
    
    if ($stmt_result->num_rows > 0) {
        // Username exists, now check the password
        $data = $stmt_result->fetch_assoc();
        $hashed_password = $data['password']; // Get the hashed password from the database

        // Verify the password using password_verify()
        if (password_verify($password, $hashed_password)) {
            echo "<h2>LOGIN SUCCESSFULLY</h2>";
            header('Location: dashboard.php');
            exit(); // Make sure to exit after redirection
        } else {
            echo "<h2>LOGIN FAILED OR INVALID PASSWORD</h2>";
        }
    } else {
        echo "<h2>LOGIN FAILED OR INVALID USERNAME</h2>";
    }
    
    $stmt->close();
    $con->close();
}
?>
