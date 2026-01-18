#ifndef COLORSTRING_HPP
#define COLORSTRING_HPP

#include <iostream>
#include <string>

#ifdef _WIN32
    #include <windows.h>
#endif  

namespace Color {
    const std::string RESET   = "\033[0m";
    const std::string ROJO    = "\033[31m";
    const std::string VERDE   = "\033[32m";
    const std::string AMARILLO = "\033[33m";
    const std::string AZUL    = "\033[34m";
    const std::string MAGENTA = "\033[35m";
    const std::string CIAN    = "\033[36m";
    const std::string NARANJA = "\033[38;5;208m";
    const std::string NARANJA_NEGRO = "\033[30;48;5;208m";
    const std::string AZUL_FONDO = "\033[30;44m";
}
#ifdef _WIN32
inline void initTerminalColors() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) return;

    DWORD dwMode = 0;
    if (GetConsoleMode(hOut,&dwMode)) {
        dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode(hOut, dwMode);
    }
}
#endif

#endif