rule MoqHao_regex_with_filesize {
   strings:
      $a = "AndroidManifest.xml"
      $b = /classes[2-9]\.dex/
      $c = /assets\/[a-z]\/\w{1,5}/
   condition:
      $a and $b and $c and filesize < 500KB
}
