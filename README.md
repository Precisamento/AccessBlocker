# AccessBlocker
Adds an option called `Block Access` when shift+right clicking on an exe file to block it from accessing the internet via windows defender.

# Building
This program only works on Windows (it may require msvc to build, is hasn't been tested with other compilers), and by default uses meson to build. There are no specific configuration options currently.

```sh
mkdir build
cd build
meson ..
ninja
```

# Installing
When built, it will create 3 executables in the build dir: `accessblocker`, `accessblocker_installer`, and `accessblocker_uninstaller`.
Simply move these to any directory you want, and run `accessblocker_installer`. 
Make sure not to move accessblocker from there or the right click method will no longer work. Uninstalling should work from any directory.

# Using
AccessBlocker is intended to be used from the right click menu on exe files, but it can also be used from the command line if preferred:

```sh
accessblocker C:\path\to\file.exe
```

It should work with relative paths as well.
