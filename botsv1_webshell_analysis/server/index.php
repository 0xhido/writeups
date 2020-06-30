<?php

/*----------------------------------------------------------------------------------------
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE in the project root for license information.
 *---------------------------------------------------------------------------------------*/

function x($t, $k)
{
    $c = strlen($k);
    $l = strlen($t);
    $o = "";
    for ($i = 0; $i < $l;) {
        for ($j = 0; ($j < $c && $i < $l); $j++, $i++) {
            $o .= $t{
            $i} ^ $k{
            $j};
        }
    }
    return $o;
}

function get_webshell_command($rr, $ra)
{
    $kh = "3481";
    $kf = "9d7b";

    if ($rr && $ra) {
        $u = parse_url($rr);
        parse_str($u["query"], $q);
        $q = array_values($q);
        preg_match_all("/([\\w])[\\w-]+(?:;q=0.([\\d]))?,?/", $ra, $m);
        if ($q && $m) {
            try {
                @session_start();
            } catch (Exception $th) {
                @session_destroy();
            }
            $s = &$_SESSION;
            $ss = "substr";
            $sl = "strtolower";
            $i = $m[1][0] . $m[1][1];
            $h = $sl($ss(md5($i . $kh), 0, 3));
            $f = $sl($ss(md5($i . $kf), 0, 3));
            $p = "";
            for ($z = 1; $z < count($m[1]); $z++) {
                $p .= $q[$m[2][$z]];
            }
            if (strpos($p, $h) === 0) {
                $s[$i] = "";
                $p = $ss($p, 3);
            }
            if (array_key_exists($i, $s)) {
                $s[$i] .= $p;
                $e = strpos($s[$i], $f);
                if ($e) {
                    $k = $kh . $kf;
                    ob_start();
                    $command = @gzuncompress(@x(@base64_decode(preg_replace(array("/_/", "/-/"), array("/", "+"), $ss($s[$i], 0, $e))), $k));
                    if ($command) {
                        print("command = " . $command . "\n");
                    }
                    $o = ob_get_contents();
                    ob_end_clean();
                    echo $o;
                    $d = base64_encode(x(gzcompress($o), $k));
                    // print("<$k>$d</$k>");
                    @session_destroy();
                }
            }
        }
    }
}

function get_string_between($string, $start, $end)
{
    $string = ' ' . $string;
    $ini = strpos($string, $start);
    if ($ini == 0) return '';
    $ini += strlen($start);
    $len = strpos($string, $end, $ini) - $ini;
    return substr($string, $ini, $len);
}

function decode_output($data)
{
    if ($data != "-") {
        $k = get_string_between($data, '<', '>');
        $base64_ecoded_command = get_string_between($data, '<' . $k . '>', '<' . $k . '/>');
        $base64_decoded_command = base64_decode($base64_ecoded_command);
        $compressed_command = x($base64_decoded_command, $k);
        $uncompressed_command = gzuncompress($compressed_command);
        echo "output = " . $uncompressed_command . "\n";
    }
}

function read_requests()
{
    $requests = fopen("./splunk_records/requests.txt", "r") or die("Unable to open file");
    $requests_data = fread($requests, filesize("./splunk_records/requests.txt"));

    $requests_array = explode("\n", $requests_data);
    foreach ($requests_array as &$request) {
        $splitted = explode(" --> ", $request);
        $refferer = trim($splitted[0]);
        $accepted_lan = trim($splitted[1]);

        get_webshell_command($refferer, $accepted_lan);
    }

    fclose($requests);
}

function read_outputs()
{
    $outputs = fopen("./splunk_records/outputs.txt", "r") or die("Unable to open file");
    $outputs_data = fread($outputs, filesize("./splunk_records/outputs.txt"));

    $outputs_array = explode("\n", $outputs_data);
    foreach ($outputs_array as &$output) {
        decode_output(trim($output));
    }

    fclose($outputs);
}

function main()
{
    $com_out_file = fopen("./splunk_records/req_and_out.txt", "r") or die("Unable to open file");
    $com_out_data = fread($com_out_file, filesize("./splunk_records/req_and_out.txt"));

    $com_out_array = explode("\n", $com_out_data);
    foreach ($com_out_array as &$com_out) {
        $splitted = explode(" --> ", $com_out);

        $refferer = trim($splitted[0]);
        $accepted_lan = trim($splitted[1]);
        $output = trim($splitted[2]);

        get_webshell_command($refferer, $accepted_lan);
        decode_output($output);
    }

    fclose($com_out_file);
}

function t()
{
    chdir('C:\inetpub\wwwroot\joomla');
    if (is_callable('posix_getpwuid') && is_callable('posix_geteuid')) {
        $u = @posix_getpwuid(@posix_geteuid());
        if ($u) {
            $u = $u['name'];
        } else {
            $u = getenv('username');
        }
        print($u);
    }

    chdir('C:\inetpub\wwwroot\joomla');
    $f = '/sbin/ifconfig';
    if (@file_exists($f)) {
        print('e');
        if (@is_readable($f)) print('r');
        if (@is_writable($f)) print('w');
        if (@is_executable($f)) print('x');
    }
}

main();
