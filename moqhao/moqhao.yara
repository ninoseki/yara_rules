rule MoqHao_regex_with_filesize {
   strings:
      $a = "AndroidManifest.xml" nocase wide ascii
      $b = /classes[2-9]\.dex/ nocase wide ascii
      $c = /assets\/[a-z]\/\w{1,5}/ nocase wide ascii
   condition:
      $a and $b and $c and filesize < 500KB
}
