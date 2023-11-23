#include <iostream>
#include <string>
#include <vector>

#include "klib.hpp"


int main(int argc, char *argv[]) {
    // read args
    klib::ProgArguments progArgs = klib::readArguments(argc, argv);

    if (progArgs.m_errCode != klib::ErrorCode::NOERROR_CODE) {
        klib::showUsage(progArgs.m_errCode, std::string(progArgs.m_errMessage == NULL ? "" : progArgs.m_errMessage));
        ::ExitProcess(progArgs.m_errCode);
    }

    // show version
    if (progArgs.m_showVersion) {
        std::cout << PACKAGE_ID << std::endl;
    }

    // read password
    char *passc = klib::readPassword(progArgs.m_keyMode, progArgs.m_subArg);
    if (passc == NULL) {
        klib::fatalError("Fetching password");
    }
    
    // Create a new console for the ssh process
    if (!::FreeConsole() || !::AllocConsole()) {
        klib::fatalError(std::string("Free/Alloc Console"));
    }

    // Launch child process
    std::string cmdLine("ssh.exe ");
    cmdLine += std::string(progArgs.m_sshArguments);
    ::SetConsoleTitleA(const_cast<char *>(cmdLine.c_str()));

    PVOID oldWow64RedValue = 0;  // disable wow 64 redirection: we want ssh.exe to be in the path
    ::Wow64DisableWow64FsRedirection(&oldWow64RedValue); 

    PROCESS_INFORMATION processInfo; // to be filled out by call to lauchProcess
    klib::launchProcess(cmdLine, false, processInfo);

    ::Wow64RevertWow64FsRedirection(oldWow64RedValue);

    // Get a handle to the console input buffer
    HANDLE hStdin = ::GetStdHandle(STD_INPUT_HANDLE);
    if (hStdin == INVALID_HANDLE_VALUE) {
        klib::fatalError(std::string("GetStdHandle on console stdin failed."));
    }

    // Get a handle to the console output buffer    
    HANDLE hStdout = ::GetStdHandle(STD_OUTPUT_HANDLE);
    if (hStdout == INVALID_HANDLE_VALUE) {
        klib::fatalError(std::string("GetStdHandle on console stdout failed."));
    }

    // Write a message showing ssh is running
    std::string waitMsg = "Running " + cmdLine + " and waiting for password prompt...\n";
    ::WriteConsoleA(hStdout, (char *) waitMsg.c_str(), waitMsg.length(), 0, 0);

    // Wait until we encounter the prompt, i.e. when the input echo is disabled in the console
    DWORD conMode = 0;
    DWORD maxWaitTime = 5 * 1000, curWaitTime = 0;
    while (::GetConsoleMode(hStdin, &conMode) && (conMode & ENABLE_ECHO_INPUT) && curWaitTime <= maxWaitTime) {
        ::WaitForSingleObject(processInfo.hProcess, 500);
        curWaitTime += 500;
    }
    bool readyForPassword = ::GetConsoleMode(hStdin, &conMode) && !(conMode & ENABLE_ECHO_INPUT);

    if (readyForPassword) {
        // Send the password
        ::FlushConsoleInputBuffer(hStdin);
        klib::sendToInputConsole(hStdin, passc);
        klib::sendToInputConsole(hStdin, "\n");
        ::SecureZeroMemory(passc, ::strlen(passc));
    }

    // Clean up
    ::CloseHandle(hStdin);
    ::CloseHandle(processInfo.hThread);    
    ::CloseHandle(processInfo.hProcess);
    ::FreeConsole();
    ::AttachConsole(-1); // return to original (parent)

    if (!readyForPassword) {
        std::cerr << "Failed: ssh.exe did not show the 'password:' prompt in time." << std::endl;
    }

    std::cerr << "Done." << std::endl;

    return 0;
}
