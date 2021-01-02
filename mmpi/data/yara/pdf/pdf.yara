rule possible_exploit
{
	meta:
        name = "possible_exploit"
        severity = 9
        type = "pdf"
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 3
		url = "https://github.com/hiddenillusion/AnalyzePDF/blob/master/pdf_rules.yara"
        description = "possible exploit"
	strings:
		$magic = { 25 50 44 46 }
		
		$attrib0 = /\/JavaScript /
		$attrib3 = /\/ASCIIHexDecode/
		$attrib4 = /\/ASCII85Decode/

		$action0 = /\/Action/
		$action1 = "Array"
		$shell = "A"
		$cond0 = "unescape"
		$cond1 = "String.fromCharCode"
		
		$nop = "%u9090%u9090"
	condition:
		$magic at 0 and (2 of ($attrib*)) or ($action0 and #shell > 10 and 1 of ($cond*)) or ($action1 and $cond0 and $nop)
}

rule suspicious_js
{
	meta:
        name = "suspicious_js"
        severity = 6
        type = "pdf"
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 3
		description = "possible exploit"
	strings:
		$magic = { 25 50 44 46 }
		
		$attrib0 = /\/OpenAction /
		$attrib1 = /\/JavaScript /

		$js0 = "eval"
		$js1 = "Array"
		$js2 = "String.fromCharCode"
		
	condition:
		$magic at 0 and all of ($attrib*) and 2 of ($js*)
}
