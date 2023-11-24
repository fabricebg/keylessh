#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <windows.h>
#include <wincred.h>

#include "klib.hpp"

namespace klib {

void sendToInputConsole(HANDLE hStdin, const char *inputMsg) {
    const int msgLength = ::strlen(inputMsg);
    INPUT_RECORD* irArray = new INPUT_RECORD[msgLength * 2];

    for (size_t i = 0; i < msgLength; ++i) {
        irArray[i * 2].EventType = KEY_EVENT;
        irArray[i * 2].Event.KeyEvent.bKeyDown = TRUE;
        irArray[i * 2].Event.KeyEvent.dwControlKeyState = 0;
        irArray[i * 2].Event.KeyEvent.uChar.UnicodeChar = inputMsg[i];
        irArray[i * 2].Event.KeyEvent.wRepeatCount = 1;
        irArray[i * 2].Event.KeyEvent.wVirtualKeyCode = 0;
        irArray[i * 2].Event.KeyEvent.wVirtualScanCode = 0;

        irArray[i * 2 + 1] = irArray[i * 2];
        irArray[i * 2 + 1].Event.KeyEvent.bKeyDown = FALSE;
    }

    // Write the input record to the console input buffer
    DWORD eventsWritten;

    if (!WriteConsoleInput(hStdin, irArray, msgLength * 2, &eventsWritten)) {
        std::cerr << "WriteConsoleInput failed" << std::endl;        
    }

    delete [] irArray;
}

char *getCredentialsFromManager(char *credName) {

    char *result = NULL;
    PCREDENTIALA pCred = NULL;
    if (::CredReadA(credName, CRED_TYPE_GENERIC, 0, &pCred)) {
        // in theory, we should work with a wide-char string
        // std::wstring pwd(reinterpret_cast<wchar_t *>(pCred->CredentialBlob), pCred->CredentialBlobSize);
        // std::wcerr << pwd << std::endl;

        // in practice, we're butchers
        result = (char *) malloc(pCred->CredentialBlobSize + 1);
        int j = 0;
        for (int i = 0; i < pCred->CredentialBlobSize; ++i) {
            BYTE curByte = pCred->CredentialBlob[i];
            if (curByte != 0) {
                result[j++] = static_cast<char>(curByte);
            }
        }

        result[j++] = 0;
    }

    return result;
}

char *getCredFromEnvironmentVariable(char *name) {
    char *result = (char *) malloc(8 * sizeof(char));

    DWORD valueLength = ::GetEnvironmentVariableA(name, result, 1);
    if (valueLength != 0) {
        free(result);
        result = (char *) malloc((valueLength + 1) * sizeof(char));
        valueLength = ::GetEnvironmentVariableA(name, result, valueLength);
        if (valueLength == 0) {
            free(result);
            result = NULL;
        }
    } else {
        free(result);
        result = NULL;
    }

    return result;
}

char *getCredFromFile(const char *fileName) {
    char *result = NULL;

    HANDLE hFile = ::CreateFileA(fileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD fileSize = ::GetFileSize(hFile, NULL);

        if (fileSize != INVALID_FILE_SIZE) {
            int bufSize = fileSize > 1024 ? fileSize : 1024;
            result = new char[bufSize + 1];
            ::ZeroMemory(result, bufSize);

            char ch;
            DWORD bytesRead;
            int curPos = 0;
            while (::ReadFile(hFile, &ch, 1, &bytesRead, NULL) && bytesRead == 1 && curPos < bufSize && ch != '\n' && ch != '\r') {
                result[curPos++] = ch;
            }

            if (curPos == 0) {
                std::cerr << "Password line is empty!" << std::endl;
                delete [] result;
                result = NULL;
            } else {
                result[curPos++] = '\0';
            }
        }
        
        ::CloseHandle(hFile);
    }

    return result;
}

char *readPassword(KeyMode keyMode, char *additionalInfo) {
    char *result = NULL;
    DWORD dwAttrib = 0;

    switch (keyMode) {
    case KeyMode::CMDLINE_KEY:
        result = additionalInfo;  // password is on the cmd line itself
        break;
    case KeyMode::CRED_MAN:
        result = getCredentialsFromManager(additionalInfo);
        break;
    case KeyMode::ENV_VAR:
        result = getCredFromEnvironmentVariable(ENVVAR_NAME);
        break;
    case KeyMode::KEY_FILE:
        dwAttrib = GetFileAttributesA(additionalInfo);

        if (dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY)) {          
            result = getCredFromFile(additionalInfo);
        } else {
            std::string operation("reading file ");
            fatalError(operation.append(additionalInfo));
        }
        break;
    case KeyMode::NONE_KEYMODE:
    default:
        std::cerr << "Password fetching method not specified." << std::endl;
        break;
    }

    return result;
}

void showUsage(ErrorCode code, const std::string &msg) {
    if (code != ErrorCode::NOERROR_CODE) {
        std::cerr << "Error" << (msg.empty() ? "" : ": " + msg + ".\n") << std::endl;
    }

    std::cerr << "Usage: keylessh.exe [options] [parameters to pass to ssh]\n"
	    "   /f filename   Take password to use from file\n"
	    "   /p password   Provide password as argument (don't)\n"
	    "   /e            Password is passed as environment variable \"" ENVVAR_NAME "\"\n"
        "   /c credname   Passsword taken from Windows Credentials Manager key \"credname\"\n"
	    "   /V            Print version information\n" << std::endl;
}

std::string findAskPass() {
	char path[MAX_PATH];
	DWORD res = GetModuleFileNameA(NULL, path, MAX_PATH);
	std::string result(path);
	result = result.append("\\ask_pass.exe");

	return result;
}

void launchProcess(std::string &cmdLine, bool createCommPipes, PROCESS_INFORMATION& pi) {
    SECURITY_ATTRIBUTES saAttr; 
	::ZeroMemory(&saAttr, sizeof(SECURITY_ATTRIBUTES));
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES); 

    STARTUPINFOA si;
    ::ZeroMemory(&si, sizeof(STARTUPINFO));
	si.cb = sizeof(STARTUPINFO);
    si.dwFlags = 0;

    // The read end of one pipe serves as standard input for the child process, 
    // and the write end of the other pipe is the standard output for the child process.
    HANDLE hChildStdinRead = NULL;
    HANDLE hChildStdinWrite = NULL;
    HANDLE hChildStdoutRead = NULL;
    HANDLE hChildStdoutWrite = NULL;

    if (createCommPipes) {
        // Set the bInheritHandle flag to TRUE so pipe handles are inherited. 
        saAttr.bInheritHandle = TRUE; 
        saAttr.lpSecurityDescriptor = NULL; 

        if (!::CreatePipe(&hChildStdoutRead, &hChildStdoutWrite, &saAttr, 0) ||
            !::SetHandleInformation(hChildStdoutRead, HANDLE_FLAG_INHERIT, 0) ||
            !::CreatePipe(&hChildStdinRead, &hChildStdinWrite, &saAttr, 0) ||
            !::SetHandleInformation(hChildStdinWrite, HANDLE_FLAG_INHERIT, 0)) {
            throw std::string("err");
        }

        // create Startup info structure with handles
        si.dwFlags |= STARTF_USESTDHANDLES;
        si.hStdError = hChildStdoutWrite;
        si.hStdOutput = hChildStdoutWrite;
        si.hStdInput = hChildStdinRead;
    }

    // The process information receives info when calling CreateProcessX
	::ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

	BOOL bRet = ::CreateProcessA(
		NULL,   // Application path
		const_cast<char *>(cmdLine.c_str()),  // Command line, including exec since 1st arg is NULL
        NULL,       // Process handle not inheritable
        NULL,       // Thread handle not inheritable
		TRUE,       // Set handle inheritance to TRUE
		0, // Detached process without console would be DETACHED_PROCESS
		NULL,       // Use parent's environment block
        NULL,       // Use parent's starting directory 
        &si,        // Pointer to STARTUPINFO structure
        &pi         // Pointer to PROCESS_INFORMATION structure
	);

	if (!bRet) {
		fatalError(std::string("CreateProcessA"));
	}

    if (createCommPipes) {
        // Close handles to the stdin and stdout pipes no longer needed by the child process.
        ::CloseHandle(hChildStdoutWrite);
        ::CloseHandle(hChildStdinRead);
    }

    // could return these handles instead of closing them
	::CloseHandle(hChildStdinWrite); // write to child process here
    ::CloseHandle(hChildStdoutRead); // read child process stdout here
}

void fatalError(const std::string &operation) {
    DWORD error = ::GetLastError();
    std::string message = std::system_category().message(error);
    std::cerr << "Failed with error " << error << ": " << message << " in operation " << operation << ".\n";
    ::ExitProcess(1);
}

char* str_join(char* array[], int start, int end) {
    // Calculate the total length of the concatenated string
    int totalLength = 1; // for the null terminator
    for (int i = start; i < end; i++) {
        totalLength += ::strlen(array[i]) + 1;
    }

    // Allocate memory for the new string
    char* result = (char *) ::malloc(totalLength * sizeof(char));

    // Initialize the result string as an empty string
    result[0] = '\0';

    // Concatenate the strings
    for (int i = start; i < end; i++) {
        ::strcat(result, array[i]);
        ::strcat(result, " ");
    }

    return result;
}

ProgArguments readArguments(int argc, char *argv[]) {
    ProgArguments args;

    args.m_errCode = NOERROR_CODE;
    args.m_keyMode = NONE_KEYMODE;
    args.m_errMessage = NULL;
    args.m_subArg = NULL;

    if (argc <= 2) {
        args.m_errCode = ErrorCode::NOT_ENOUGH_ARGS;
        args.m_errMessage = "Please specify at least one argument";
    } else {
        int sshParamIndexStart = 1;
        for (int i = 1; i < argc && args.m_errCode == ErrorCode::NOERROR_CODE; ++i) {
            char *curArg = argv[i];
            KeyMode newKeyMode = KeyMode::NONE_KEYMODE;

            if (strcmp(curArg, "/f") == 0) {
                newKeyMode = KeyMode::KEY_FILE;
                if (i < argc - 1) {
                    args.m_subArg = argv[i + 1];
                    ++i;
                } else {
                    args.m_errCode = ErrorCode::INVALID_USAGE;
                }
            } else if (strcmp(curArg, "/p") == 0) {
                newKeyMode = KeyMode::CMDLINE_KEY;
                if (i < argc - 1) {
                    args.m_subArg = argv[i + 1];
                    ++i;
                } else {
                    args.m_errCode = ErrorCode::INVALID_USAGE;
                }
            } else if (strcmp(curArg, "/c") == 0) {
                newKeyMode = KeyMode::CRED_MAN;
                if (i < argc - 1) {
                    args.m_subArg = argv[i + 1];
                    ++i;
                } else {
                    args.m_errCode = ErrorCode::INVALID_USAGE;
                }
            } else if (strcmp(curArg, "/e") == 0) {
                newKeyMode = KeyMode::ENV_VAR;
            } else if (strcmp(curArg, "/V") == 0) {
                args.m_showVersion = true;
            } else {
                sshParamIndexStart = i; // must be ssh param                
                i = argc;  // exit loop
            }

            if (args.m_errCode == ErrorCode::NOERROR_CODE) {
                if (newKeyMode != KeyMode::NONE_KEYMODE) {
                    if (args.m_keyMode == KeyMode::NONE_KEYMODE) {
                        args.m_keyMode = newKeyMode;
                    } else {
                        args.m_errCode = ErrorCode::INVALID_USAGE;
                        args.m_errMessage = "Multiple key modes specified; pick one";
                    }
                }
            }
        } // for loop on args

        if (args.m_errCode == ErrorCode::NOERROR_CODE) {
            if (sshParamIndexStart >= argc) {
                args.m_errCode = ErrorCode::NO_SSH_PARAM;
                args.m_errMessage = "No parameters to pass to ssh were specified";
            } else {
                args.m_sshArguments = str_join(argv, sshParamIndexStart, argc);
            }
        }
    }

    return args;
}

}
