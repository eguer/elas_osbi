file(REMOVE_RECURSE
  "CMakeFiles/tools"
  "scripts"
  "scripts/gdb.sh"
  "scripts/run-qemu.sh"
  "scripts/test-qemu.sh"
  "scripts/travis.sh"
)

# Per-language clean rules from dependency scanning.
foreach(lang )
  include(CMakeFiles/tools.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
