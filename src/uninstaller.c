#define _WIN32_WINNT 0x0600

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 2048

int main(void) {
    char buffer[BUFFER_SIZE];
    DWORD buffer_size = BUFFER_SIZE;
    HKEY key = NULL;
    HKEY shell = NULL;
    LSTATUS error;

    error = RegGetValueA(HKEY_CLASSES_ROOT, ".exe", NULL, RRF_RT_REG_SZ, NULL, &buffer, &buffer_size);
    if(error != ERROR_SUCCESS)
        goto err;

    strcat(buffer, "\\shell");
    error = RegOpenKeyEx(HKEY_CLASSES_ROOT,
                         buffer,
                         0,
                         KEY_ALL_ACCESS,
                         &shell);

    if(error != ERROR_SUCCESS)
        goto err;

    strcat(buffer, "\\Block Access");
    error = RegOpenKeyEx(HKEY_CLASSES_ROOT,
                         buffer,
                         0,
                         KEY_ALL_ACCESS,
                         &key);

    if(error != ERROR_SUCCESS)
        goto err;

    error = RegDeleteKey(key, "command");
    if(error != ERROR_SUCCESS)
        goto err;

    RegCloseKey(key);

    error = RegDeleteKey(shell, "Block Access");
    if(error != ERROR_SUCCESS)
        goto err;

    RegCloseKey(shell);

    return EXIT_SUCCESS;

    err:
        if(shell != NULL)
            RegCloseKey(key);

        if(key != NULL)
            RegCloseKey(key);
        
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM,
                      NULL,
                      error,
                      0,
                      buffer,
                      buffer_size,
                      NULL);

        fprintf(stderr, "Error: %s\n", buffer);
        return EXIT_FAILURE;
}