#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
#include <windows.h>
#include <dbt.h>         // For WM_DEVICECHANGE
#include <iostream>
#include <fstream>
#include <string>
#include <chrono>        // For timestamps
#include <iomanip>       // For formatting timestamps
#include <filesystem>    // For path manipulation (C++17)
#include <shlobj.h>      // For GetModuleFileNameW potentially needed alt path
#include <initguid.h>    // Should be included once before headers defining GUIDs

// {A5DCBF10-6530-11D2-901F-00C04FB951ED} - GUID_DEVINTERFACE_USB_DEVICE
// Define it here since we included initguid.h
DEFINE_GUID(GUID_DEVINTERFACE_USB_DEVICE, 0xA5DCBF10L, 0x6530, 0x11D2, 0x90, 0x1F, 0x00, 0xC0, 0x4F, 0xB9, 0x51, 0xED);


// --- Global Variables ---
std::ofstream g_logFile;
std::filesystem::path g_logFilePath;
const char* g_logFileName = "SecurityMonitorLog.txt";
HWND g_hwnd = NULL; // Handle to our hidden message-only window

// --- Function Prototypes ---
std::string GetTimestamp();
void LogEvent(const std::string& message);
void LogError(const std::string& context, DWORD errorCode);
std::filesystem::path GetExecutableDirectory();
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
bool RegisterDeviceNotifications(HWND hwnd);

// --- Implementation ---

// Get current timestamp as string
std::string GetTimestamp() {
    try {
        auto now = std::chrono::system_clock::now();
        auto now_c = std::chrono::system_clock::to_time_t(now);
        std::tm now_tm;
        localtime_s(&now_tm, &now_c); // Use safer localtime_s on Windows
        std::stringstream ss;
        ss << std::put_time(&now_tm, "[%Y-%m-%d %H:%M:%S] ");
        return ss.str();
    } catch (const std::exception& e) {
        std::cerr << "Error getting timestamp: " << e.what() << std::endl;
        return "[TIMESTAMP_ERROR] ";
    }
}

// Log an event to the file and console
void LogEvent(const std::string& message) {
    std::string timedMessage = GetTimestamp() + message;
    std::cout << timedMessage << std::endl; // Also print to console for visibility
    if (g_logFile.is_open()) {
        g_logFile << timedMessage << std::endl;
        g_logFile.flush(); // Ensure it's written immediately
        if (g_logFile.fail()) {
             std::cerr << GetTimestamp() << "FATAL: Failed to write to log file '" << g_logFilePath.string() << "'!" << std::endl;
             // Consider more drastic action here? Maybe try reopening?
        }
    } else {
         std::cerr << GetTimestamp() << "ERROR: Log file is not open. Cannot log: " << message << std::endl;
    }
}

// Log an error, including Windows error code
void LogError(const std::string& context, DWORD errorCode) {
     LPSTR messageBuffer = nullptr;
     size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                  NULL, errorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

     std::string errorMessage(messageBuffer, size);
     LocalFree(messageBuffer); // Free the buffer allocated by FormatMessage

     std::string logMsg = "ERROR in " + context + ": " + errorMessage + " (Code: " + std::to_string(errorCode) + ")";
     LogEvent(logMsg); // Log it like a regular event
}

// Get the directory where the executable is running
std::filesystem::path GetExecutableDirectory() {
    wchar_t path[MAX_PATH] = {0};
    // Use GetModuleFileNameW for Unicode path support
    if (GetModuleFileNameW(NULL, path, MAX_PATH) == 0) {
        DWORD error = GetLastError();
         std::cerr << "FATAL: Failed to get executable path. Error code: " << error << std::endl;
         // Fallback or exit? For now, return current dir, but log the error severely.
         LogError("GetExecutableDirectory/GetModuleFileNameW", error);
         return std::filesystem::current_path();
    }
    std::filesystem::path exePath(path);
    return exePath.parent_path(); // Return the directory part
}


// Window Procedure to handle messages
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_DESTROY:
            LogEvent("Window destroyed, stopping message loop.");
            PostQuitMessage(0);
            return 0;

        case WM_CLIPBOARDUPDATE:
            LogEvent("Clipboard content changed (Copy/Paste detected).");
            return 0;

        case WM_DEVICECHANGE:
        {
            // Check if it's a device arrival or removal
            if (wParam == DBT_DEVICEARRIVAL || wParam == DBT_DEVICEREMOVECOMPLETE) {
                 PDEV_BROADCAST_HDR pHdr = (PDEV_BROADCAST_HDR)lParam;
                 if (pHdr != nullptr && pHdr->dbch_devicetype == DBT_DEVTYP_DEVICEINTERFACE) {
                     PDEV_BROADCAST_DEVICEINTERFACE pDevInf = (PDEV_BROADCAST_DEVICEINTERFACE)pHdr;

                     // Check if it's a USB device interface
                     // Compare pDevInf->dbcc_classguid with GUID_DEVINTERFACE_USB_DEVICE
                     if (IsEqualGUID(pDevInf->dbcc_classguid, GUID_DEVINTERFACE_USB_DEVICE)) {
                         std::wstring devPathW(pDevInf->dbcc_name);
                         // Convert wide string path to narrow string for logging (potential data loss if non-ASCII)
                         // A more robust solution would involve wide char logging or careful conversion
                         int size_needed = WideCharToMultiByte(CP_UTF8, 0, &devPathW[0], (int)devPathW.size(), NULL, 0, NULL, NULL);
                         std::string devPathA(size_needed, 0);
                         WideCharToMultiByte(CP_UTF8, 0, &devPathW[0], (int)devPathW.size(), &devPathA[0], size_needed, NULL, NULL);

                         if (wParam == DBT_DEVICEARRIVAL) {
                             LogEvent("USB Device Plugged In: " + devPathA);
                             // NOTE: This is where you'd add logic to check if it's "unusual"
                         } else { // DBT_DEVICEREMOVECOMPLETE
                             LogEvent("USB Device Removed: " + devPathA);
                         }
                     } else {
                        // Log other device interface changes - might hint at driver installs sometimes
                         std::wstring devPathW(pDevInf->dbcc_name);
                         int size_needed = WideCharToMultiByte(CP_UTF8, 0, &devPathW[0], (int)devPathW.size(), NULL, 0, NULL, NULL);
                         std::string devPathA(size_needed, 0);
                         WideCharToMultiByte(CP_UTF8, 0, &devPathW[0], (int)devPathW.size(), &devPathA[0], size_needed, NULL, NULL);

                         if (wParam == DBT_DEVICEARRIVAL) {
                             LogEvent("Non-USB Device Interface Arrival (Potential Driver/Software Install?): " + devPathA);
                         } else {
                             LogEvent("Non-USB Device Interface Removal: " + devPathA);
                         }
                     }

                 }
                 // Could also check for DBT_DEVTYP_VOLUME here for drive letters appearing/disappearing
                 else if (pHdr != nullptr && pHdr->dbch_devicetype == DBT_DEVTYP_VOLUME) {
                    PDEV_BROADCAST_VOLUME pVol = (PDEV_BROADCAST_VOLUME)pHdr;
                    if(wParam == DBT_DEVICEARRIVAL) {
                        // Get drive letter
                        char driveLetter = '?';
                        DWORD driveMask = pVol->dbcv_unitmask;
                        for (char i = 0; i < 26; ++i) {
                            if (driveMask & (1 << i)) {
                                driveLetter = 'A' + i;
                                break;
                            }
                        }
                        LogEvent("Volume/Drive Mounted: " + std::string(1, driveLetter) + ":\\");
                    } else if (wParam == DBT_DEVICEREMOVECOMPLETE) {
                         // Similar logic to find drive letter if needed
                        LogEvent("Volume/Drive Removed.");
                    }
                 }
            }
            // Add detection for app installs here (VERY HARD - see notes)
            // For example, a *very basic* placeholder could just log *any* device change:
            // LogEvent("WM_DEVICECHANGE message received (wParam=" + std::to_string(wParam) + "). Check logs for specifics.");

            return TRUE; // Indicate message was handled
        }

        default:
            // Let Windows handle other messages
            return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
}

// Register for device notifications
bool RegisterDeviceNotifications(HWND hwnd) {
    DEV_BROADCAST_DEVICEINTERFACE notificationFilter = {0};
    notificationFilter.dbcc_size = sizeof(DEV_BROADCAST_DEVICEINTERFACE);
    notificationFilter.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
    // Optionally filter by GUID, e.g., GUID_DEVINTERFACE_USB_DEVICE
    // notificationFilter.dbcc_classguid = GUID_DEVINTERFACE_USB_DEVICE; // Uncomment to only get USB *interface* notifications

    HDEVNOTIFY hDevNotify = RegisterDeviceNotification(
        hwnd,                       // events recipient
        &notificationFilter,        // type of device
        DEVICE_NOTIFY_WINDOW_HANDLE // type of recipient handle
        // | DEVICE_NOTIFY_ALL_INTERFACE_CLASSES // Use this instead of specifying GUID to get all interfaces
    );

    if (hDevNotify == NULL) {
        LogError("RegisterDeviceNotification", GetLastError());
        return false;
    }
    // Note: We don't store hDevNotify globally here because we'd need to unregister it
    // during WM_DESTROY, which might be complex if the app is terminated abruptly.
    // The OS usually cleans up notifications when the window is destroyed.
    LogEvent("Successfully registered for device notifications.");
    return true;
}


int main() {
    // 1. Determine Project/Executable Directory and Log File Path
    std::filesystem::path projectDir;
    try {
        projectDir = GetExecutableDirectory();
        g_logFilePath = projectDir / g_logFileName;
         std::cout << "Project Directory (Executable Location): " << projectDir.string() << std::endl;
         std::cout << "Log file path: " << g_logFilePath.string() << std::endl;
    } catch (const std::exception& e) {
         std::cerr << "FATAL: Could not determine executable directory: " << e.what() << std::endl;
         return 1; // Cannot proceed without log path
    }


    // 2. Open Log File
    // Use std::ios::app to append to the file if it exists
    g_logFile.open(g_logFilePath, std::ios::app);
    if (!g_logFile.is_open()) {
        std::cerr << GetTimestamp() << "FATAL: Could not open log file: " << g_logFilePath.string() << std::endl;
        // Log error using system means if possible (maybe event log?)
        // Or just exit
        return 1;
    }

    LogEvent("--- SecurityMonitor Started ---");
    LogEvent("Project Directory: " + projectDir.string());

    // 3. Create a message-only window to receive system messages
    const wchar_t CLASS_NAME[] = L"SecurityMonitorMessageWindowClass";

    WNDCLASSW wc = {}; // Use WNDCLASSW for Unicode
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = GetModuleHandle(NULL); // Get instance handle
    wc.lpszClassName = CLASS_NAME;

    if (!RegisterClassW(&wc)) {
         LogError("RegisterClassW", GetLastError());
         g_logFile.close(); // Close log before exiting
         return 1;
    }

    // Create a message-only window (doesn't appear on screen)
    // HWND_MESSAGE allows receiving messages like WM_DEVICECHANGE without a visible window
    g_hwnd = CreateWindowExW(
        0,                      // Optional window styles.
        CLASS_NAME,             // Window class
        L"SecurityMonitor Hidden Window", // Window text (not visible)
        0,                      // Window style (not visible)
        0, 0, 0, 0,             // Size and position (irrelevant)
        HWND_MESSAGE,           // Parent window -> Message-Only Window!
        NULL,                   // Menu
        GetModuleHandle(NULL),  // Instance handle
        NULL                    // Additional application data
    );

    if (g_hwnd == NULL) {
        LogError("CreateWindowExW (Message Window)", GetLastError());
        g_logFile.close();
        return 1;
    }

    LogEvent("Message-only window created successfully.");

    // 4. Register for Clipboard Notifications
    if (!AddClipboardFormatListener(g_hwnd)) {
        LogError("AddClipboardFormatListener", GetLastError());
        // Continue running, but log the failure
        LogEvent("WARNING: Failed to register clipboard listener. Copy/Paste events will not be logged.");
    } else {
         LogEvent("Successfully registered clipboard listener.");
    }

    // 5. Register for Device Notifications (USB, etc.)
    if (!RegisterDeviceNotifications(g_hwnd)) {
        // Error already logged by the function
        LogEvent("WARNING: Failed to register device notifications. USB/Device events may not be logged accurately.");
        // Decide whether to continue or exit based on severity
    }

    // 6. Message Loop (Run indefinitely)
    LogEvent("Starting message loop. Monitoring active...");
    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0) > 0) { // GetMessage returns > 0 for messages other than WM_QUIT
        TranslateMessage(&msg);
        DispatchMessage(&msg); // Sends message to WindowProc
    }

    // --- Cleanup (only reached if PostQuitMessage is called) ---
    LogEvent("--- SecurityMonitor Stopping ---");

    // Unregister listeners (optional but good practice if shutdown is clean)
    RemoveClipboardFormatListener(g_hwnd); // No return value check needed/possible easily
    // UnregisterDeviceNotification requires the HDEVNOTIFY handle, which we didn't store globally for simplicity.
    // The OS cleans this up when the window is destroyed anyway.

    DestroyWindow(g_hwnd); // Destroy the hidden window

    if (g_logFile.is_open()) {
        g_logFile.close();
    }

    return (int)msg.wParam; // Return quit code
}