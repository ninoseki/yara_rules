rule FakeCop {
   strings:
      $manifest = "AndroidManifest.xml"
      $jiagu_a = "assets/libjiagu.so"
      $jiagu_b = "assets/libjiagu_x86.so"
      $wav = /assets\/[0-1]{1,3}\.wav/
      $key = "assets/.appkey"
   condition:
      $manifest and ($jiagu_a or $jiagu_b) and $wav and $key and filesize > 10MB
}
