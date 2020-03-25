project('AccessBlocker', 'c', 'cpp',
    default_options: ['cpp_std=vc++latest'],
    version: '0.0.1'
)

cpp = meson.get_compiler('cpp')

has_filesystem = cpp.has_header('filesystem') or cpp.has_header('experimental/filesystem')

if has_filesystem
    accessblocker = executable('accessblocker',
        './src/accessblocker.cpp'
    )
else
    shlwapi = cpp.find_library('Shlwapi',
        required: true)

    pathcch = cpp.find_library('Pathcch',
        required: true)

    deps = [shlwapi, pathcch]
    
    accessblocker = executable('accessblocker',
        './src/accessblocker.cpp',
        dependencies: deps
    )
endif

installer = executable('accessblocker_installer',
    './src/installer.c'
)

uninstaller = executable('accessblocker_uninstaller',
    './src/uninstaller.c'
)