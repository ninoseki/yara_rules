rule FakeSpy {
   strings:
      $a = "AndroidManifest.xml"
      $b = "lib/armeabi/librig.so"
      $c = "lib/armeabi-v7a/librig.so"
   condition:
      $a and ($b or $c) and (filesize > 2MB and filesize < 3MB)
}
