<?php
require_once __DIR__ . '/lib/render.php';
logout_user();
header('Location: ' . base_url() . '/index.php');
