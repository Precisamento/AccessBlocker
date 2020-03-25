#include <Windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 2048

int main(void) {
    char buffer[BUFFER_SIZE];
    DWORD buffer_size = BUFFER_SIZE;
    HKEY key = NULL;
    HKEY command = NULL;
    DWORD status;
    LSTATUS error = RegGetValue(HKEY_CLASSES_ROOT, ".exe", NULL, RRF_RT_REG_SZ, NULL, &buffer, &buffer_size);

    if(error != ERROR_SUCCESS)
        goto err;

    strcat(buffer, "\\shell\\Block Access");

    error = RegCreateKeyEx(HKEY_CLASSES_ROOT, 
                           buffer, 
                           0, 
                           NULL, 
                           REG_OPTION_NON_VOLATILE, 
                           KEY_WRITE | KEY_READ, 
                           NULL, 
                           &key, 
                           &status);

    if(error != ERROR_SUCCESS)
        goto err;

    if(status != REG_CREATED_NEW_KEY) {
        fprintf(stderr, "%s\n", "AccessBlocker is already installed.");
        abort();
    }
    
    error = RegCreateKeyEx(key,
                   "command",
                   0,
                   NULL,
                   REG_OPTION_NON_VOLATILE,
                   KEY_WRITE | KEY_READ,
                   NULL,
                   &command,
                   &status);

    if(error != ERROR_SUCCESS)
        goto err;

    if(GetCurrentDirectory(BUFFER_SIZE, buffer) == 0) {
        error = GetLastError();
        goto err;
    }

    strcat(buffer, "\\accessblocker.exe %1");

    error = RegSetValueExA(command, NULL, 0, REG_SZ, buffer, strlen(buffer) + 1);
    if(error != ERROR_SUCCESS)
        goto err;

    // Specifies that the option should only appear when pressing
    // shift + right click.
    error = RegSetValueExA(key, "Extended", 0, REG_SZ, NULL, 0);
    if(error != ERROR_SUCCESS)
        goto err;

    RegCloseKey(command);
    RegCloseKey(key);

    return EXIT_SUCCESS;

    err:
        if(command)
            RegCloseKey(command);
        if(key)
            RegCloseKey(key);
        FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, NULL, error, 0, buffer, BUFFER_SIZE, NULL);
        fprintf(stderr, "%s\n", buffer);
        return EXIT_FAILURE;
}