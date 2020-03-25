#include <comdef.h>
#include <netfw.h>
#include <objbase.h>
#include <stringapiset.h>
#include <Windows.h>
#include <winerror.h>
#include <cwchar>
#include <cstdio>
#include <string>

#ifdef __cpp_lib_filesystem
    #include <filesystem>
    namespace fs = std::filesystem;
#elif __cpp_lib_experimental_filesystem
    #include <experimental/filesystem>
    namespace fs = std::experimental::filesystem;
#else
    // If filesystem doesn't exist, assume that the application
    // passed to this program is an absolute path.
    #define ASSUME_ABSOLUTE_PATH
    #include <pathcch.h>
    #include <shlwapi.h>
#endif

// This part is technically possible in plain old c, but
// it's honestly easier to just use c++ with a c style.


bool try_create_firewall_policy2(INetFwPolicy2** policy);
HRESULT create_firewall_rules(const wchar_t* app_name);
HRESULT init_rule(INetFwRule** rule);
HRESULT create_rule(INetFwRule** rule, 
                    NET_FW_RULE_DIRECTION direction, 
                    const wchar_t* rule_name, 
                    const wchar_t* rule_description, 
                    const wchar_t* app_path);
bool need_rule(INetFwRules* rules, const wchar_t* rule_name, HRESULT* out_error);
HRESULT remove_app_firewall_authorization(const wchar_t* app_name);
bool app_needs_to_be_blocked(INetFwAuthorizedApplications* apps, BSTR app_path);

int main(int argc, char** argv) {
    if(argc < 2) {
        fprintf(stderr, "Must pass an application path as an argument to AccessBlocker.\n");
        return EXIT_FAILURE;
    }

    HRESULT hr = S_OK;

    wchar_t buffer[4096];
    wchar_t* argument;
    bool name_on_stack = true;
    int buffer_size = 4096;
    int result = EXIT_SUCCESS;
    
#ifdef ASSUME_ABSOLUTE_PATH
    wchar_t* ext;
    bool path_on_stack = false;
    wchar_t* app_path;
#else
    fs::path abs_path;
    const wchar_t* app_path;
#endif

    if(MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, argv[1], -1, buffer, buffer_size) == 0) {
        int error = GetLastError();
        if(error == ERROR_INSUFFICIENT_BUFFER) {
            buffer_size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, argv[1], -1, NULL, 0);
            argument = new wchar_t[buffer_size];
            name_on_stack = false;

            if(MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, argv[1], -1, argument, buffer_size) == 0)
                goto err;
        } else {
            char* error_buffer;
            FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, 
                          NULL, 
                          error, 
                          0, 
                          (LPSTR)&error_buffer, 
                          0, 
                          NULL);

            if(error_buffer) {
                fprintf(stderr, "Error with application name: %s\n", error_buffer);
                LocalFree(error_buffer);
            }
        }
    } else {
        argument = buffer;
    }

#ifdef ASSUME_ABSOLUTE_PATH
    hr = PathAllocCanonicalize(argument, PATHCCH_NONE, &app_path);
    if(FAILED(hr))
        goto err;

    // PathAllocCanonicalize does not get the full path
    // like the std::filesystem version,
    // so we need to get the full path name if it was relative.
    if(PathIsRelativeW(app_path)) {
        if(GetFullPathNameW(app_path, buffer_size, buffer, NULL) == 0) {
            hr = GetLastError();
            goto err;
        }

        LocalFree(app_path);
        path_on_stack = true;
        app_path = buffer;
    }

    if(!PathFileExistsW(app_path)) {
        fprintf(stderr, "Path does not exist: %ls\n", app_path);
        goto err;
    }

    ext = PathFindExtensionW(app_path);
    if(*ext == L'\0' || wcscmp(ext, L".exe") != 0) {
        fprintf(stderr, "Expected an executable name.\n");
        goto err;
    }
#else
    abs_path = fs::canonical(argument);
    if(!fs::exists(abs_path)) {
        fprintf(stderr, "PAth does not exist: %ls\n", abs_path.c_str());
        goto err;
    }

    if(abs_path.extension() != ".exe") {
        fprintf(stderr, "Expected an executable name.\n");
        goto err;
    }

    app_path = abs_path.c_str();
#endif

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED | COINIT_SPEED_OVER_MEMORY);
    if(FAILED(hr))
        goto err;

    if(FAILED(create_firewall_rules(app_path)))
        goto err;

    if(FAILED(remove_app_firewall_authorization(app_path)))
        goto err;

    goto cleanup;

    err:
        fputs("Encountered Error:", stderr);
        if(FAILED(hr)) {
            _com_error error(hr);
            fprintf(stderr, "Error: %s\n", error.ErrorMessage());
        }

        result = EXIT_FAILURE;

    cleanup:
        if(!name_on_stack)
            delete[] argument;

#ifdef ASSUME_ABSOLUTE_PATH
        if(!path_on_stack && app_path)
            LocalFree(app_path);
#endif

        if(SUCCEEDED(hr))
            CoUninitialize();

        return result;
}

HRESULT create_firewall_rules(const wchar_t* app_path) {
    HRESULT hr;
    INetFwPolicy2* policy = NULL;
    INetFwRules* rules = NULL;
    INetFwRule* inbound_rule = NULL;
    INetFwRule* outbound_rule = NULL;
    wchar_t app_name[_MAX_FNAME + 1] = {0};
    std::wstring name;
    bool add_inbound = false, add_outbound = false;

    // It's ok if the policy cannot be created, just
    // means that windows firewall isn't running.
    // The application can still be blocked by other means,
    // so it isn't a fail state.
    if(!try_create_firewall_policy2(&policy))
        return S_OK;

    hr = policy->get_Rules(&rules);
    if(FAILED(hr))
        goto cleanup;

    _wsplitpath_s(app_path, NULL, 0, NULL, 0, app_name, _MAX_FNAME, NULL, 0);

    // Make the inbound rule
    name.append(app_name);
    name.append(L" Inbound");

    if(need_rule(rules, name.c_str(), &hr)) {
        if(FAILED(hr))
            goto cleanup;

        hr = create_rule(&inbound_rule,
                         NET_FW_RULE_DIR_IN,
                         name.c_str(), 
                         L"Stops the application from receiving network data.", 
                         app_path);
        if(FAILED(hr))
            goto cleanup;
        add_inbound = true;
    } else if (FAILED(hr))
        goto cleanup;

    // Make the outbound rule
    name.clear();
    name.append(app_name);
    name.append(L" Outbound");

    if(need_rule(rules, name.c_str(), &hr)) {
        if(FAILED(hr))
            goto cleanup;

        hr = create_rule(&outbound_rule, 
                         NET_FW_RULE_DIR_OUT,
                         name.c_str(), 
                         L"Stops the application from sending network data.", 
                         app_path);
        if(FAILED(hr))
            goto cleanup;
        add_outbound = true;
    } else if(FAILED(hr))
        goto cleanup;

    if(add_inbound) {
        hr = rules->Add(inbound_rule);
        if(FAILED(hr))
            goto cleanup;
    }

    if(add_outbound) {
        hr = rules->Add(outbound_rule);
        if(FAILED(hr))
            goto cleanup;
    }

    cleanup:
        if(outbound_rule)
            outbound_rule->Release();
        if(inbound_rule)
            inbound_rule->Release();
        if(rules)
            rules->Release();
        if(policy)
            policy->Release();

        if(FAILED(hr)) {
            _com_error error(hr);
            fprintf(stderr, "Error trying to create firewall rules: %s\n", error.ErrorMessage());
        }

        return hr;
}

bool try_create_firewall_policy2(INetFwPolicy2** policy) {
    HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2),
                                  NULL,
                                  CLSCTX_INPROC_SERVER,
                                  __uuidof(INetFwPolicy2),
                                  (void**)policy);

    return SUCCEEDED(hr);
}

HRESULT init_rule(INetFwRule** rule) {
    return CoCreateInstance(__uuidof(NetFwRule),
                            NULL,
                            CLSCTX_INPROC_SERVER,
                            __uuidof(INetFwRule),
                            (void**)rule);
}

HRESULT create_rule(INetFwRule** rule, 
                    NET_FW_RULE_DIRECTION direction, 
                    const wchar_t* rule_name, 
                    const wchar_t* rule_description, 
                    const wchar_t* app_path) 
{
    HRESULT hr = S_OK;
    BSTR name = SysAllocString(rule_name);
    BSTR description = SysAllocString(rule_description);
    BSTR path = SysAllocString(app_path);
    INetFwRule* inst;

    if(!name || !description || !path) {
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }

    hr = init_rule(rule);
    if(FAILED(hr))
        goto cleanup;

    inst = *rule;

    inst->put_Name(name);
    inst->put_Description(description);
    inst->put_ApplicationName(path);
    inst->put_Action(NET_FW_ACTION_BLOCK);
    inst->put_Direction(direction);
    inst->put_Enabled(VARIANT_TRUE);

    cleanup:
        if(name)
            SysFreeString(name);

        if(description)
            SysFreeString(description);

        if(path)
            SysFreeString(path);

        return hr;
}

bool need_rule(INetFwRules* rules, const wchar_t* name, HRESULT* out_error) {
    INetFwRule* rule;
    BSTR rule_name = SysAllocString(name);
    *out_error = S_OK;

    if(!rule_name) {
        *out_error = E_OUTOFMEMORY;
        return false;
    }

    bool result = true;

    HRESULT hr = rules->Item(rule_name, &rule);

    SysFreeString(rule_name);

    if(SUCCEEDED(hr)) {
        rule->Release();
        return false;
    }

    if(hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND))
        return true;

    *out_error = hr;
    return false;
}

HRESULT remove_app_firewall_authorization(const wchar_t* app_path) {
    HRESULT hr;
    INetFwMgr* firewall_manager = NULL;
    INetFwPolicy* firewall_policy = NULL;
    INetFwProfile* firewall_profile = NULL;
    INetFwAuthorizedApplications* firewall_authorized_apps = NULL;
    BSTR path = NULL;

    hr = CoCreateInstance(__uuidof(NetFwMgr), 
                          NULL, 
                          CLSCTX_INPROC_SERVER, 
                          __uuidof(INetFwMgr), 
                          (void**)&firewall_manager);
    if(FAILED(hr))
        goto err;

    hr = firewall_manager->get_LocalPolicy(&firewall_policy);
    if(FAILED(hr))
        goto err;

    hr = firewall_policy->get_CurrentProfile(&firewall_profile);
    if(FAILED(hr))
        goto err;

    hr = firewall_profile->get_AuthorizedApplications(&firewall_authorized_apps);
    if(FAILED(hr))
        goto err;

    path = SysAllocString(app_path);
    if(!path)
        goto err;

    if(!app_needs_to_be_blocked(firewall_authorized_apps, path))
        return S_OK;

    hr = firewall_authorized_apps->Remove(path);

    SysFreeString(path);

    err:
        if(firewall_authorized_apps)
            firewall_authorized_apps->Release();
        if(firewall_profile)
            firewall_policy->Release();
        if(firewall_policy)
            firewall_policy->Release();
        if(firewall_manager)
            firewall_manager->Release();
        return hr;
}

bool app_needs_to_be_blocked(INetFwAuthorizedApplications* apps, BSTR app_path) {
    INetFwAuthorizedApplication* app;
    // This will check if the app is currently authorized.
    // If the value is retrieved, it needs to be blocked.
    // For any other result (invalid name, already blocked, etc...)
    // no action is necessary.
    HRESULT hr = apps->Item(app_path, &app);
    if(hr == S_OK) {
        app->Release();
        return true;
    }

    return false;
}