rule MoqHao_regex_with_filesize {
   strings:
      $zip = /^PK/ ascii
      $manifest = "AndroidManifest.xml"
      $dex_a = "classes.dex"
      $dex_b = /classes[2-9]\.dex/
      $assets_a = /assets\/[a-z]\/\w{1,5}/
      $assets_b = /assets\/\w{1,10}\/\w{1,10}/
   condition:
      $zip and $manifest and ($dex_a or $dex_b) and ($assets_a or $assets_b) and filesize < 500KB
}
