rule matches_file_1
{
    meta:
        description = "Unknown dynamic loader code, probably for ads"
        proxy_action = "passthrough"
        sample_file = "samples/file1.js"

    strings:
        $sspapi = "sspapi."
        $zenyou = "zenyou."
        $zdRndNum = "zdRndNum(10)"
        $js_suffix = "/js?i="

    condition:
        $sspapi and $zenyou and $zdRndNum and $js_suffix
}


rule matches_file_2
{
    meta:
        description = "Obfuscated payment data exfiltration code"
        proxy_action = "block"
        sample_file = "samples/file2.js"

    strings:
        $has_obf_hex_identifiers = /\b_0x[0-9a-fA-F]+[0-9a-fA-F]*\b/
        $high_entropy_b64_field_name = "input-cc-expire-date" base64
        $exfil_b64_url = "cdn-report.com/status/" base64
        $localstorage_key = "'bmmuw'"

    condition:
        $has_obf_hex_identifiers and
        $high_entropy_b64_field_name and
        $exfil_b64_url and
        $localstorage_key
}


rule matches_file_3
{
    meta:
        description = "Unknown site acceleration loader"
        proxy_action = "passthrough"
        sample_file = "samples/file3.js"

    strings:
        $sheets_proxy_url = "mysite-sheets.com/sheets_proxy"
        $high_entropy_css1 = ".mysite-launcher-frame"
        $high_entropy_css2 = ".mysite-messenger"
        $high_entropy_js = "window.__mysiteAssignLocation=function("

    condition:
        $sheets_proxy_url and
        $high_entropy_css1 and
        $high_entropy_css2 and
        $high_entropy_js
}


rule matches_file_4
{
    meta:
        description = "A very basic JS key and form logger"
        proxy_action = "block"
        sample_file = "samples/file4.js"

    strings:
        $high_entropy_var_name = "externURLKeys"
        $high_entropy_console_error = "Failed to send analytics: "
        $keydown_event = /addEventListener.*?keydown/

    condition:
        $high_entropy_var_name and
        $high_entropy_console_error and
        $keydown_event
}
