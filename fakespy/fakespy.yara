rule FakeSpy {
   strings:
      $manifest = "AndroidManifest.xml"
      $lib_a = "lib/armeabi/librig.so"
      $lib_b = "lib/armeabi-v7a/librig.so"
   condition:
      $manifest and ($lib_a or $lib_b) and (filesize > 2MB and filesize < 3MB)
}
