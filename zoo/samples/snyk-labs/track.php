<?php 

	$output = print_r($_POST, true);
    $file = time();
    $filename = $file.'.txt';
	file_put_contents($filename	, $output);

