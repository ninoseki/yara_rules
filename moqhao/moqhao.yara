rule MoqHao_regex_with_filesize {
   strings:
      $manifest = "AndroidManifest.xml"
      $dex = /classes[2-9]\.dex/
      $assets_a = /assets\/[a-z]\/\w{1,5}/
      $assets_b = /assets\/\w{1,10}\/\w{1,10}/
   condition:
      $manifest and $dex and ($assets_a or $assets_b) and filesize < 500KB
}
