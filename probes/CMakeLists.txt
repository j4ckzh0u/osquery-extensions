cmake_minimum_required(VERSION 3.12.1)

function(probesMain)
  generateProbe("execve")
endfunction()

function(generateProbe probe_name)
  set(common_header_file "${CMAKE_CURRENT_SOURCE_DIR}/common.h")
  set(input_source_file "${CMAKE_CURRENT_SOURCE_DIR}/${probe_name}/main.c")

  set(include_dir "${CMAKE_CURRENT_BINARY_DIR}/..")
  set(output_source_file "${CMAKE_CURRENT_BINARY_DIR}/${probe_name}.h")

  add_custom_command(
    OUTPUT "${output_source_file}"
    COMMAND bash -c "printf 'namespace probes {\\nstatic const std::string ${probe_name} = R\"(\\n'" > "${output_source_file}"
    COMMAND bash -c "cat '${common_header_file}'" >> "${output_source_file}"
    COMMAND bash -c "cat '${input_source_file}'" >> "${output_source_file}"
    COMMAND bash -c "printf '\\n)\";\\n}\\n'" >> "${output_source_file}"
    DEPENDS "${input_source_file}"
    COMMENT "Generating probe: ${probe_name}"
    VERBATIM
  )

  add_custom_target("${probe_name}_probe_generator"
    DEPENDS "${output_source_file}"
  )

  add_library("${probe_name}_probe" INTERFACE)
  target_include_directories("${probe_name}_probe" INTERFACE
    "${include_dir}"
    "${CMAKE_CURRENT_SOURCE_DIR}/.."
  )
  add_dependencies("${probe_name}_probe" "${probe_name}_probe_generator")
endfunction()

probesMain()
