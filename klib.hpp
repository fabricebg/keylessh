#ifndef __KLIBHPP__
#define __KLIBHPP__

#include <iostream>
#include <string>
#include <windows.h>

#define PACKAGE_ID "keylessh 1.0.0"
#define ENVVAR_NAME "KEYLESSHPWD"


namespace klib {

typedef enum _KeyMode {
    NONE_KEYMODE,
    KEY_FILE,
    CMDLINE_KEY,
    ENV_VAR,
    CRED_MAN, // Windows Credentials Manager
} KeyMode;

typedef enum _ErrorCode {
    NOERROR_CODE,
    NOT_ENOUGH_ARGS,
    INVALID_USAGE,
    NO_SSH_PARAM,
} ErrorCode;

typedef struct _ProgArguments {
    ErrorCode m_errCode = NOERROR_CODE;
    KeyMode m_keyMode = NONE_KEYMODE;
    char *m_errMessage = NULL;
    char *m_subArg = NULL;
    bool m_showVersion = false;
    char *m_sshArguments = NULL;
} ProgArguments;

ProgArguments readArguments(int argc, char *argv[]);

char *readPassword(KeyMode keyMode, char *additionalInfo);

std::string findAskPass();

void showUsage(ErrorCode code, const std::string &msg);

void launchProcess(std::string &cmdLine, bool createCommPipes, PROCESS_INFORMATION& pi);

void fatalError(const std::string &operation);

void sendToInputConsole(HANDLE hStdin, const char *inputMsg);

}


#endif