/*
    AutoIR_MCP starter YARA rules.

    These rules target high-signal fragments commonly found in incident
    response samples. They are intentionally small and should be extended with
    environment-specific rules. scan_yara downloads one remote file and runs
    this rule set locally.
*/

rule AutoIR_Reverse_Shell
{
    meta:
        description = "Reverse shell command fragments"
        author = "AutoIR_MCP"
        severity = "high"
    strings:
        $bash_i = "bash -i" ascii wide nocase
        $dev_tcp = "/dev/tcp/" ascii
        $nc_e = "nc -e" ascii wide nocase
        $socat_exec = "socat exec:" ascii wide nocase
        $mkfifo_sh = "mkfifo" ascii wide nocase
    condition:
        $dev_tcp or $nc_e or $socat_exec or ($bash_i and $mkfifo_sh)
}

rule AutoIR_Crypto_Miner
{
    meta:
        description = "Cryptocurrency miner indicators"
        author = "AutoIR_MCP"
        severity = "high"
    strings:
        $stratum = "stratum+tcp://" ascii wide nocase
        $xmrig = "xmrig" ascii wide nocase
        $minerd = "minerd" ascii wide nocase
        $donate = "donate.v2.xmrig.com" ascii wide nocase
        $randomx = "randomx" ascii wide nocase
    condition:
        any of them
}

rule AutoIR_Webshell_PHP
{
    meta:
        description = "PHP webshell execution patterns"
        author = "AutoIR_MCP"
        severity = "high"
    strings:
        $post_eval = "eval($_POST" ascii nocase
        $request_eval = "eval($_REQUEST" ascii nocase
        $post_assert = "assert($_POST" ascii nocase
        $post_base64 = "base64_decode($_POST" ascii nocase
        $get_system = "system($_GET" ascii nocase
        $request_passthru = "passthru($_REQUEST" ascii nocase
        $cookie_eval = "eval($_COOKIE" ascii nocase
    condition:
        any of them
}
